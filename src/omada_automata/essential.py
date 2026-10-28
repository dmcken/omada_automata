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
confirmed live end-to-end. See _network_check.py for the shared
protocol (identical to an on-premise controller's) - this class just
builds the org/site-scoped POST path and WebSocket subscribe
destination:

    POST {org_id}/api/v2/sites/{site_id}/tools/network-check/{test}
    subscribe: /user/queue/ws/{org_id}/sites/{site_id}/status

`interfaceId`/`interfaceType` (for a Gateway source doing Ping/
Traceroute) and destType 1 client-targeted tests are documented in
_network_check.py but NOT confirmed live specifically on Essential
Controller (confirmed on-premise only, on the identical backend).

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

import logging
import time

from . import _envelope, _network_check, exceptions, models

logger = logging.getLogger(__name__)

_CONTROLLER_WAKING_UP_ERROR_CODE = -1200
_WAKEUP_RETRY_DELAYS_SECONDS = (2, 5, 10)

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

    def _ws_url(self) -> str:
        ws_base = self._base_url.replace('https://', 'wss://', 1).replace('http://', 'ws://', 1)
        return f"{ws_base}/{self._org_id}/ws/status"

    def _cookie_header(self) -> str:
        return '; '.join(f"{c.name}={c.value}" for c in self._session.cookies)

    def _run_network_check(
        self,
        site_id: str,
        test: int,
        source_macs: list[str],
        extra_body: dict,
        device_type: int,
        timeout: float,
    ) -> dict[str, str]:
        return _network_check.run(
            post_fn=self._post,
            post_path=f'/{self._org_id}/api/v2/sites/{site_id}/tools/network-check/{test}',
            ws_url=self._ws_url(),
            origin=self._frontend_origin or self._base_url,
            cookie_header=self._cookie_header(),
            csrf_token=self._csrf_token,
            subscribe_destination=f'/user/queue/ws/{self._org_id}/sites/{site_id}/status',
            device_type=device_type,
            source_macs=source_macs,
            extra_body=extra_body,
            timeout=timeout,
        )

    def ping(
        self,
        site_id: str,
        source_macs: list[str],
        dest: str | None = None,
        dest_client_mac: str | None = None,
        packet_size: int = 32,
        count: int = 4,
        device_type: int = 0,
        interface_id: str | None = None,
        interface_type: int | None = None,
        timeout: float = _network_check.DEFAULT_TIMEOUT,
    ) -> dict[str, str]:
        '''Ping `dest` (a hostname or IP) or a known client
        (`dest_client_mac`) from each of `source_macs`. Confirmed live
        end-to-end, including output format. `interface_id`/
        `interface_type` are for a Gateway source (device_type=2) - see
        _network_check.py.

        Returns:
            dict[str, str]: source MAC -> raw ping output text.
        '''
        extra = _network_check.dest_body(dest, dest_client_mac)
        extra['packetSize'] = packet_size
        extra['count'] = count
        if interface_id is not None:
            extra['interfaceId'] = interface_id
        if interface_type is not None:
            extra['interfaceType'] = interface_type
        return self._run_network_check(
            site_id, _network_check.TEST_PING, source_macs, extra, device_type, timeout
        )

    def traceroute(
        self,
        site_id: str,
        source_macs: list[str],
        dest: str | None = None,
        dest_client_mac: str | None = None,
        device_type: int = 0,
        interface_id: str | None = None,
        interface_type: int | None = None,
        timeout: float = _network_check.DEFAULT_TIMEOUT,
    ) -> dict[str, str]:
        '''Traceroute to `dest` (a hostname or IP) or a known client
        (`dest_client_mac`) from each of `source_macs`. Confirmed live
        end-to-end, including output format. `interface_id`/
        `interface_type` are for a Gateway source (device_type=2) - see
        _network_check.py.

        Returns:
            dict[str, str]: source MAC -> raw traceroute output text.
        '''
        extra = _network_check.dest_body(dest, dest_client_mac)
        if interface_id is not None:
            extra['interfaceId'] = interface_id
        if interface_type is not None:
            extra['interfaceType'] = interface_type
        return self._run_network_check(
            site_id, _network_check.TEST_TRACEROUTE, source_macs, extra, device_type, timeout
        )

    def dns_lookup(
        self,
        site_id: str,
        source_macs: list[str],
        hostname: str,
        device_type: int = 0,
        timeout: float = _network_check.DEFAULT_TIMEOUT,
    ) -> dict[str, str]:
        '''Resolve `hostname` from each of `source_macs`. Confirmed live
        end-to-end, including output format.

        Returns:
            dict[str, str]: source MAC -> raw DNS lookup output text.
        '''
        extra = _network_check.dest_body(hostname, None)
        return self._run_network_check(
            site_id, _network_check.TEST_DNS_LOOKUP, source_macs, extra, device_type, timeout
        )

    def arp_table(
        self,
        site_id: str,
        source_macs: list[str],
        device_type: int = 0,
        timeout: float = _network_check.DEFAULT_TIMEOUT,
    ) -> dict[str, str]:
        '''Dump the ARP table of each of `source_macs`. Confirmed live
        end-to-end, including output format - note its output never
        gets an explicit "finish" signal from the server on Essential
        Controller (see module docstring), so this relies on a
        quiet-period heuristic instead and may wait up to ~20s past the
        last chunk before returning.

        Returns:
            dict[str, str]: source MAC -> raw ARP table output text.
        '''
        return self._run_network_check(
            site_id, _network_check.TEST_ARP_TABLE, source_macs, {}, device_type, timeout
        )
