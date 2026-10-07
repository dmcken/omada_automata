'''Omada Essential Controller - the cloud-hosted per-organization site
controller (sites/devices/clients/alerts/dashboard).

Never construct this directly - get one via
OmadaCloudAccount.essential_controller(org_id), which discovers the
right (regional, per-organization) base URL via Cloud Manager's hosts
endpoint and hands it this account's already-authenticated session and
CSRF token.

Confirmed live (one real "Omada Essential" free-tier organization, two
sites - one with an ER605 gateway/SG2206MP switch/EAP720 AP, one empty):
user/sites, organization/site-ids, current/user-detail, site/alerts/num,
get_devices(), get_clients(), get_dashboard_overview(). The latter three
still return the raw decoded `result` value rather than a parsed
dataclass - the request shapes came from the web UI's own traffic and
the response shapes have now been confirmed live too, but no dataclass
has been built for them yet (real field names: devices are keyed by
`type` - "gateway"/"switch"/"ap" - each with model/mac/sn/firmware/cpu-
and-mem-util/traffic counters; clients similarly have `connectDevType`,
mac/ip/vendor, per-type traffic; dashboard overview is a list of
per-device-type count summaries). Treat the exact key set as liable to
vary by device/plan until checked against more than one account.

Two path styles are used under the same base_url, both confirmed live:
- {org_id}/api/v2/...        - internal web-UI API (undocumented,
  session cookie + Csrf-Token only - this is what the Omada Cloud web
  UI itself calls).
- openapi/v1|v2/{org_id}/... - same backend surface, under the path
  convention TP-Link's documented "Open API" also uses. Normally that
  API is reached via a separate OAuth2 client-credentials flow with a
  registered API client, but this account's plan doesn't have that
  enabled (`account/addons` returns "showAccountOpenApi": false) -
  confirmed these openapi/* routes still work fine authenticated the
  same way as api/v2 (session + Csrf-Token), which is how the web UI
  itself calls them when Open API access isn't set up.

Network check tools (ping()/traceroute()/dns_lookup()/arp_table()):
confirmed live end-to-end for all four (two rounds - Ping from the
original HAR, Traceroute/DNS-Lookup/ARP-Table's request shape from a
second capture, output for all four from live calls through this
module itself). All four go to the same endpoint family:

    POST {org_id}/api/v2/sites/{site_id}/tools/network-check/{test}
    {"deviceType", "source": [macs], "nid": <random correlation token>,
     ...test-specific fields, see below...}
    -> {"result": {"deviceResult": [{"errorCode", "mac", "nid"}, ...]}}

`test` is 0=Ping, 1=Traceroute, 2=DNS Lookup, 3=ARP Table (confirmed
from the frontend's own enum, and each test number's exact body
confirmed live). This POST only ever acknowledges the test was queued
per device - it never carries the actual output. Ping/Traceroute/DNS
Lookup also take `destType` (0=hostname-or-IP, in which case `dest`
holds it; 1=a known client, in which case `client` holds its MAC) -
ARP Table takes no destination at all. Ping alone also takes
`packetSize`/`count`. NOT confirmed live: `interfaceId` (the frontend
adds it for deviceType Gateway doing Ping/Traceroute, to pick a WAN -
never exercised against a real gateway) and destType 1 client-targeted
tests (only destType 0 host/IP-targeted tests were tried).

The actual output streams back over a WebSocket, not this POST's
response - see _sockjs_stomp.py for the transport and
_run_network_check() below for how it's consumed. The server pushes
one or more STOMP MESSAGE frames to
`/user/queue/ws/{org_id}/sites/{site_id}/status`, each shaped
{"type":"troubleshootingTest","data":{"nid","mac","seq","finish","msg"}}
- `msg` is base64-encoded raw device CLI output text (literally the
device's own command's stdout - `ping`, `traceroute`, `nslookup`,
`arp`), `seq` numbers the chunks in order. Confirmed live for
Ping/Traceroute/DNS Lookup: the last chunk has `finish:true`.
NOT true for ARP Table - confirmed live that its one output chunk
(the complete table, at least for the single-entry table tried) never
gets `finish:true`, even waiting 45s past it with nothing further
arriving - `_run_network_check()` falls back to a quiet-period
heuristic (_NETWORK_CHECK_IDLE_TIMEOUT below) for exactly this reason,
rather than only ever trusting `finish`.

Shiro priming call: confirmed live that every data call made against a
just-logged-in EssentialController fails with errorCode -1200 ("You
have been logged out of the controller ... Please try to log in again
later") until GET {org_id}/api/v2/current/login-status?needToken=true
has been called at least once first - after that, every other endpoint
works fine, including with the *original* CSRF token from
OmadaCloudAccount.login(), not whatever (different) csrfToken
login-status itself returns. current/login-status's own
"needShiroLogin": true in its response is misleading here - it stays
true even after this priming call has made every other endpoint work,
so it can't be used as a "do I still need to call this" signal; treat
calling it once per EssentialController instance as mandatory instead.
_ensure_shiro_login() does this lazily on first use of _get()/_post().
This was originally misread as the free-tier controller needing a few
seconds to "cold start" (retrying the same failing call with backoff
did eventually stop being necessary once this priming call was added,
which is what exposed the real mechanism) - _WAKEUP_RETRY_DELAYS_SECONDS
below is kept as a defensive fallback for genuine transient blips, not
the primary fix.
'''
from __future__ import annotations

import base64
import logging
import time
import uuid

from . import _envelope, exceptions, models

logger = logging.getLogger(__name__)

_CONTROLLER_WAKING_UP_ERROR_CODE = -1200
_WAKEUP_RETRY_DELAYS_SECONDS = (2, 5, 10)

TEST_PING = 0
TEST_TRACEROUTE = 1
TEST_DNS_LOOKUP = 2
TEST_ARP_TABLE = 3

# get_devices()'s raw `status` field is a numeric code with no dataclass to
# decode it yet (see the module docstring). 14 was confirmed live (an
# ER605/SG2206MP/EAP720 all showing "Connected" in the Omada UI); the rest
# map to the Omada UI's other device status labels. Treat any value not
# listed here as unknown rather than assuming it means disconnected.
DEVICE_STATUS = {
    0: 'Disconnected',
    10: 'Provisioning',
    11: 'Configuring',
    12: 'Upgrading',
    13: 'Rebooting',
    14: 'Connected',
}
DEVICE_STATUS_UNKNOWN = 'Unknown'


def device_status_label(status: int | None) -> str:
    '''Omada UI label for a get_devices() entry's raw `status` code -
    DEVICE_STATUS_UNKNOWN for anything not (yet) in DEVICE_STATUS,
    including a missing status.'''
    return DEVICE_STATUS.get(status, DEVICE_STATUS_UNKNOWN)

_DEFAULT_NETWORK_CHECK_TIMEOUT = 70.0
# Confirmed live: ARP Table's single output chunk never gets a
# finish:true (unlike Ping/Traceroute/DNS Lookup, all confirmed to set
# it correctly) - waited 45s with nothing further arriving. Falling
# back to "no frame at all (not even a heartbeat) for this long ->
# treat as done" - comfortably above the ~9s gaps observed live between
# Ping's own chunks, so it won't cut those short, while still ending
# ARP Table's wait long before the overall timeout above.
_NETWORK_CHECK_IDLE_TIMEOUT = 20.0


class EssentialController:
    '''One organization's Essential Controller - sites, devices,
    clients, alerts.
    '''

    def __init__(
        self,
        session,
        org_id: str,
        base_url: str,
        csrf_token: str | None,
        frontend_origin: str | None = None,
        timeout: int = 30,
    ) -> None:
        self._session = session
        self._org_id = org_id
        self._base_url = base_url.rstrip('/')
        self._csrf_token = csrf_token
        self._frontend_origin = frontend_origin
        self._timeout = timeout
        self._shiro_login_done = False

    def _headers(self) -> dict:
        headers = {
            'X-Requested-With': 'XMLHttpRequest',
            'Omada-Request-Source': 'web-local',
        }
        if self._csrf_token:
            headers['Csrf-Token'] = self._csrf_token
        return headers

    def _ensure_shiro_login(self) -> None:
        '''Prime this controller's session - see the module docstring.
        A no-op after the first call on this instance.
        '''
        if self._shiro_login_done:
            return
        resp = self._session.get(
            f"{self._base_url}/{self._org_id}/api/v2/current/login-status",
            params={'needToken': 'true'},
            headers=self._headers(),
            timeout=self._timeout,
        )
        _envelope.unwrap(resp, 'current/login-status')
        self._shiro_login_done = True

    def _get(self, path: str, params: dict | None = None):
        self._ensure_shiro_login()
        return self._request_with_wakeup_retry(
            path,
            lambda: self._session.get(
                f"{self._base_url}{path}",
                params=params,
                headers=self._headers(),
                timeout=self._timeout,
            ),
        )

    def _post(self, path: str, json_body: dict | None = None):
        self._ensure_shiro_login()
        return self._request_with_wakeup_retry(
            path,
            lambda: self._session.post(
                f"{self._base_url}{path}",
                json=json_body,
                headers=self._headers(),
                timeout=self._timeout,
            ),
        )

    def _request_with_wakeup_retry(self, path: str, send):
        '''Send one request, retrying with backoff if (and only if) it
        fails with the controller-waking-up error code - see the module
        docstring.
        '''
        last_exc = None
        for delay in (0, *_WAKEUP_RETRY_DELAYS_SECONDS):
            if delay:
                logger.info(
                    "Controller for %s not ready yet (errorCode %s), retrying in %ss",
                    path, _CONTROLLER_WAKING_UP_ERROR_CODE, delay,
                )
                time.sleep(delay)
            try:
                return _envelope.unwrap(send(), path)
            except exceptions.ApiError as exc:
                if exc.error_code != _CONTROLLER_WAKING_UP_ERROR_CODE:
                    raise
                last_exc = exc
        raise last_exc

    def get_sites(self) -> list[models.Site]:
        '''List every site (user/sites) this organization's current
        user has access to.
        '''
        result = self._get(
            f'/{self._org_id}/api/v2/user/sites',
            params={'currentPage': 1, 'currentPageSize': 100},
        )
        return [
            models.Site(site_id=s['id'], name=s.get('name', ''), favorite=s.get('favorite', False))
            for s in result.get('data', [])
        ]

    def get_site_ids(self) -> list[str]:
        '''Just the site IDs (organization/site-ids) - cheaper than
        get_sites() when names aren't needed.
        '''
        result = self._get(f'/{self._org_id}/api/v2/organization/site-ids')
        return result.get('siteIds', [])

    def get_current_user(self) -> models.CurrentUser:
        '''The logged-in user's identity and site access
        (current/user-detail).
        '''
        result = self._get(f'/{self._org_id}/api/v2/current/user-detail')
        priv = result.get('sitePrivilege', {})
        return models.CurrentUser(
            user_id=result['id'],
            email=result.get('email', ''),
            name=result.get('name', ''),
            role_id=result.get('roleId', ''),
            role_name=result.get('roleName', ''),
            user_level=result.get('userLevel', 0),
            site_privilege=models.SitePrivilege(
                all_sites=priv.get('all', False),
                service_type=priv.get('serviceType', 0),
                site_ids=priv.get('sites', []),
            ),
        )

    def get_alert_count(self, site_id: str) -> int:
        '''Active alert count for one site (site/alerts/num).'''
        result = self._get(f'/{self._org_id}/api/v2/sites/{site_id}/site/alerts/num')
        return result.get('alertNum', 0)

    def get_devices(self, site_id: str, page: int = 1, page_size: int = 100) -> dict:
        '''Raw grid/devices page for one site - APs/switches/gateways,
        each keyed by `type`, confirmed live (see module docstring) but
        not yet parsed into a dataclass - inspect the returned dict
        before relying on specific keys.
        '''
        return self._get(
            f'/{self._org_id}/api/v2/sites/{site_id}/grid/devices',
            params={'currentPage': page, 'currentPageSize': page_size, 'asyncColumns': 'client'},
        )

    def get_clients(
        self, site_id: str, active_only: bool = True, page: int = 1, page_size: int = 100
    ) -> dict:
        '''Raw clients page for one site (openapi/v2 clients search),
        confirmed live (see module docstring) but not yet parsed into a
        dataclass - inspect the returned dict before relying on
        specific keys.
        '''
        return self._post(
            f'/openapi/v2/{self._org_id}/sites/{site_id}/clients',
            json_body={
                'filters': {'active': active_only},
                'sorts': {},
                'page': page,
                'pageSize': page_size,
                'scope': 1,
            },
        )

    def get_dashboard_overview(self, site_id: str) -> list[dict]:
        '''Raw dashboard/card/overview for one site - a list of
        per-device-type count summaries, confirmed live (see module
        docstring) but not yet parsed into a dataclass.
        '''
        return self._get(f'/openapi/v1/{self._org_id}/sites/{site_id}/dashboard/card/overview')

    def _dest_body(self, dest: str | None, dest_client_mac: str | None) -> dict:
        if dest_client_mac:
            return {'destType': 1, 'client': dest_client_mac}
        if dest is None:
            raise ValueError("Either dest or dest_client_mac must be given")
        return {'destType': 0, 'dest': dest}

    def _run_network_check(
        self,
        site_id: str,
        test: int,
        source_macs: list[str],
        extra_body: dict,
        device_type: int,
        timeout: float,
    ) -> dict[str, str]:
        '''Run one network-check test and collect its output per source
        device - see the module docstring for the protocol (a REST POST
        to queue the test, then its actual output streamed back over a
        WebSocket). Blocks until every queued device's output finishes
        or `timeout` elapses.

        Requires the `network-check` extra (websocket-client).

        Returns:
            dict[str, str]: source MAC -> its decoded, concatenated
                output text.

        Raises:
            exceptions.ApiError: The test was rejected outright, or a
                queued device reported its own error.
            TimeoutError: Not every device's output finished in time.
            _sockjs_stomp.StompError: The WebSocket/STOMP handshake or
                connection itself failed.
        '''
        from . import _sockjs_stomp  # local import: only this needs the 'network-check' extra

        nid = uuid.uuid4().hex
        body = {'deviceType': device_type, 'source': list(source_macs), 'nid': nid, **extra_body}

        ws_base = self._base_url.replace('https://', 'wss://', 1).replace('http://', 'ws://', 1)
        ws_url = f"{ws_base}/{self._org_id}/ws/status"
        origin = self._frontend_origin or self._base_url
        cookie_header = '; '.join(f"{c.name}={c.value}" for c in self._session.cookies)

        client = _sockjs_stomp.SockJsStompClient(
            ws_url, origin, cookie_header, self._csrf_token or '', timeout=timeout
        )
        try:
            client.subscribe(f'/user/queue/ws/{self._org_id}/sites/{site_id}/status')

            result = self._post(
                f'/{self._org_id}/api/v2/sites/{site_id}/tools/network-check/{test}',
                json_body=body,
            )
            pending_macs = set()
            for device_result in result.get('deviceResult', []):
                if device_result.get('errorCode') != 0:
                    raise exceptions.ApiError(
                        device_result.get('errorCode', -1),
                        f"Device {device_result.get('mac')} rejected the test",
                        f'network-check/{test}',
                    )
                pending_macs.add(device_result['mac'])

            chunks: dict[str, list[tuple[int, str]]] = {}
            for message in client.iter_messages(idle_timeout=_NETWORK_CHECK_IDLE_TIMEOUT):
                if message.get('type') != 'troubleshootingTest':
                    continue
                data = message.get('data', {})
                if data.get('nid') != nid:
                    continue
                mac = data.get('mac')
                chunks.setdefault(mac, []).append((data.get('seq', 0), data.get('msg', '')))
                if data.get('finish'):
                    pending_macs.discard(mac)
                if not pending_macs:
                    break

            return {mac: _decode_network_check_chunks(parts) for mac, parts in chunks.items()}
        finally:
            client.close()

    def ping(
        self,
        site_id: str,
        source_macs: list[str],
        dest: str | None = None,
        dest_client_mac: str | None = None,
        packet_size: int = 32,
        count: int = 4,
        device_type: int = 0,
        timeout: float = _DEFAULT_NETWORK_CHECK_TIMEOUT,
    ) -> dict[str, str]:
        '''Ping `dest` (a hostname or IP) or a known client
        (`dest_client_mac`) from each of `source_macs`. Confirmed live
        end-to-end, including output format.

        Returns:
            dict[str, str]: source MAC -> raw ping output text.
        '''
        extra = self._dest_body(dest, dest_client_mac)
        extra['packetSize'] = packet_size
        extra['count'] = count
        return self._run_network_check(site_id, TEST_PING, source_macs, extra, device_type, timeout)

    def traceroute(
        self,
        site_id: str,
        source_macs: list[str],
        dest: str | None = None,
        dest_client_mac: str | None = None,
        device_type: int = 0,
        timeout: float = _DEFAULT_NETWORK_CHECK_TIMEOUT,
    ) -> dict[str, str]:
        '''Traceroute to `dest` (a hostname or IP) or a known client
        (`dest_client_mac`) from each of `source_macs`. Confirmed live
        end-to-end, including output format.

        Returns:
            dict[str, str]: source MAC -> raw traceroute output text.
        '''
        extra = self._dest_body(dest, dest_client_mac)
        return self._run_network_check(
            site_id, TEST_TRACEROUTE, source_macs, extra, device_type, timeout
        )

    def dns_lookup(
        self,
        site_id: str,
        source_macs: list[str],
        hostname: str,
        device_type: int = 0,
        timeout: float = _DEFAULT_NETWORK_CHECK_TIMEOUT,
    ) -> dict[str, str]:
        '''Resolve `hostname` from each of `source_macs`. Confirmed live
        end-to-end, including output format.

        Returns:
            dict[str, str]: source MAC -> raw DNS lookup output text.
        '''
        extra = self._dest_body(hostname, None)
        return self._run_network_check(
            site_id, TEST_DNS_LOOKUP, source_macs, extra, device_type, timeout
        )

    def arp_table(
        self,
        site_id: str,
        source_macs: list[str],
        device_type: int = 0,
        timeout: float = _DEFAULT_NETWORK_CHECK_TIMEOUT,
    ) -> dict[str, str]:
        '''Dump the ARP table of each of `source_macs`. Confirmed live
        end-to-end, including output format - note its output never
        gets an explicit "finish" signal from the server (see module
        docstring), so this relies on a quiet-period heuristic instead
        and may wait up to ~20s past the last chunk before returning.

        Returns:
            dict[str, str]: source MAC -> raw ARP table output text.
        '''
        return self._run_network_check(
            site_id, TEST_ARP_TABLE, source_macs, {}, device_type, timeout
        )


def _decode_network_check_chunks(parts: list[tuple[int, str]]) -> str:
    parts.sort(key=lambda p: p[0])
    return ''.join(base64.b64decode(msg).decode('utf-8', errors='replace') for _, msg in parts)
