'''On-premise Omada Controller (hardware, e.g. an OC200) accessed
remotely through TP-Link's Cloud Access proxy - a different product
from the cloud-hosted Essential Controller (essential.py), but running
what's confirmed live to be the *same* underlying controller software:
every endpoint below (sites, devices, clients, alerts, network-check)
uses the identical request/response shapes Essential Controller does,
just reached through a different base URL and without Essential's
Shiro-priming-call requirement (confirmed live: on-premise data calls
just work immediately after connecting, no equivalent quirk observed).

Never construct this directly - get one via
OmadaCloudAccount.onpremise_controller(device_id), which discovers the
controller's connector URL via list_onpremise_controllers() and
establishes a session for it via Cloud Access's startLaunch.

Confirmed live (one real OC200 v2.0, controller software 6.3.0.45, one
site with an EAP650/ES206GP switch/the OC200 itself): user/sites,
organization/site-ids, grid/devices/adopted, clients (openapi/v2),
alerts/num, and all four network-check tools including their output.

Base URL structure - everything below is relative to `connector_base`
(= {connectorUrl}/omadac/{device_id}, both confirmed live from
list_onpremise_controllers()):
- /{omadac_id}/api/v2/...        - internal web-UI API, same style as
  Essential Controller's {org_id}/api/v2/... (session cookie +
  Csrf-Token only).
- /openapi/v1|v2/{omadac_id}/... - same backend surface under the
  openapi path convention, matching Essential Controller's
  openapi/v1|v2/{org_id}/... exactly.
- /{omadac_id}/ws/status/...     - the real-time status WebSocket
  (network-check results) - see _sockjs_stomp.py and _network_check.py.

Notable difference from Essential Controller, confirmed live:
grid/devices/adopted and the network-check POST
(.../api/v2/tools/network-check/{test}) take no site_id in their path
at all - this controller's own devices/tests aren't site-scoped the
way Essential's URLs are. The network-check WebSocket *subscription*
destination still is site-scoped though
(/user/queue/ws/{omadac_id}/sites/{site_id}/status, confirmed live) -
so ping()/traceroute()/dns_lookup()/arp_table() below still take
site_id, just don't thread it into the POST path.

Auth: the exact same session cookies + Csrf-Token
OmadaCloudAccount.login() established are used here too, confirmed
live (traced one Csrf-Token value all the way from Cloud Manager
through Cloud Access's startLaunch to this controller's own API calls)
- no separate per-controller login step.
'''
from __future__ import annotations

from . import _envelope, _network_check, models


class OnPremiseController:
    '''One on-premise hardware controller (e.g. an OC200) - sites,
    devices, clients, alerts, network-check tools.
    '''

    def __init__(
        self,
        session,
        device_id: str,
        omadac_id: str,
        connector_base: str,
        csrf_token: str | None,
        frontend_origin: str | None = None,
        timeout: int = 30,
    ) -> None:
        self._session = session
        self._device_id = device_id
        self._omadac_id = omadac_id
        self._base_url = connector_base.rstrip('/')
        self._csrf_token = csrf_token
        self._frontend_origin = frontend_origin
        self._timeout = timeout

    def _headers(self) -> dict:
        headers = {'X-Requested-With': 'XMLHttpRequest'}
        if self._csrf_token:
            headers['Csrf-Token'] = self._csrf_token
        return headers

    def _get(self, path: str, params: dict | None = None):
        resp = self._session.get(
            f"{self._base_url}{path}",
            params=params,
            headers=self._headers(),
            timeout=self._timeout,
        )
        return _envelope.unwrap(resp, path)

    def _post(self, path: str, json_body: dict | None = None):
        resp = self._session.post(
            f"{self._base_url}{path}",
            json=json_body,
            headers=self._headers(),
            timeout=self._timeout,
        )
        return _envelope.unwrap(resp, path)

    def get_sites(self) -> list[models.Site]:
        '''List every site (user/sites) on this controller.'''
        result = self._get(
            f'/{self._omadac_id}/api/v2/user/sites',
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
        result = self._get(f'/{self._omadac_id}/api/v2/organization/site-ids')
        return result.get('siteIds', [])

    def get_alert_count(self) -> int:
        '''Active alert count for this whole controller (alerts/num) -
        unlike Essential Controller, this isn't site-scoped.
        '''
        result = self._get(f'/{self._omadac_id}/api/v2/alerts/num')
        return result.get('alertNum', 0)

    def get_devices(self, page: int = 1, page_size: int = 100) -> dict:
        '''Raw grid/devices/adopted page - APs/switches/gateways across
        every site on this controller (not site-scoped, see module
        docstring), each keyed by `type`, confirmed live but not yet
        parsed into a dataclass - inspect the returned dict before
        relying on specific keys.
        '''
        return self._get(
            f'/{self._omadac_id}/api/v2/grid/devices/adopted',
            params={'currentPage': page, 'currentPageSize': page_size, 'asyncColumns': 'client'},
        )

    def get_clients(
        self, site_id: str, active_only: bool = True, page: int = 1, page_size: int = 100
    ) -> dict:
        '''Raw clients page for one site (openapi/v2 clients search) -
        confirmed live, identical shape to Essential Controller's, not
        yet parsed into a dataclass - inspect the returned dict before
        relying on specific keys.
        '''
        return self._post(
            f'/openapi/v2/{self._omadac_id}/sites/{site_id}/clients',
            json_body={
                'filters': {'active': active_only},
                'sorts': {},
                'page': page,
                'pageSize': page_size,
                'scope': 1,
            },
        )

    def _ws_url(self) -> str:
        ws_base = self._base_url.replace('https://', 'wss://', 1).replace('http://', 'ws://', 1)
        return f"{ws_base}/{self._omadac_id}/ws/status"

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
            post_path=f'/{self._omadac_id}/api/v2/tools/network-check/{test}',
            ws_url=self._ws_url(),
            origin=self._frontend_origin or self._base_url,
            cookie_header=self._cookie_header(),
            csrf_token=self._csrf_token,
            subscribe_destination=f'/user/queue/ws/{self._omadac_id}/sites/{site_id}/status',
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
        `interface_type` are for a Gateway source (device_type=2),
        confirmed live required there - see _network_check.py.

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
        `interface_type` are for a Gateway source (device_type=2),
        confirmed live required there - see _network_check.py.

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
        end-to-end, including output format - unlike Essential
        Controller, this was confirmed live to correctly get
        `finish:true` from the server here, but the idle-timeout
        fallback (see _network_check.py) still applies defensively.

        Returns:
            dict[str, str]: source MAC -> raw ARP table output text.
        '''
        return self._run_network_check(
            site_id, _network_check.TEST_ARP_TABLE, source_macs, {}, device_type, timeout
        )
