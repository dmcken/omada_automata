'''Omada Essential Controller - the cloud-hosted per-organization site
controller (sites/devices/clients/alerts/dashboard).

Never construct this directly - get one via
OmadaCloudAccount.essential_controller(org_id), which discovers the
right (regional, per-organization) base URL via Cloud Manager's hosts
endpoint and hands it this account's already-authenticated session and
CSRF token.

Confirmed live (one real "Omada Essential" free-tier organization, two
sites): user/sites, organization/site-ids, current/user-detail,
site/alerts/num. Endpoint paths and query/body shapes for
get_devices()/get_clients()/get_dashboard_overview() are confirmed from
the requests actually sent by the web UI, but their *response* bodies
were not captured (the devtools HAR export this was built from recorded
those responses' byte size but not their content) - those three return
the raw decoded `result` value rather than a parsed dataclass. Treat
their shape as unconfirmed until checked against a live account.

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
'''
from __future__ import annotations

from . import _envelope, models


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
        timeout: int = 30,
    ) -> None:
        self._session = session
        self._org_id = org_id
        self._base_url = base_url.rstrip('/')
        self._csrf_token = csrf_token
        self._timeout = timeout

    def _headers(self) -> dict:
        headers = {
            'X-Requested-With': 'XMLHttpRequest',
            'Omada-Request-Source': 'web-local',
        }
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
        '''Raw grid/devices page for one site - APs/switches/gateways.
        Response shape unconfirmed, see module docstring - inspect the
        returned dict before relying on specific keys.
        '''
        return self._get(
            f'/{self._org_id}/api/v2/sites/{site_id}/grid/devices',
            params={'currentPage': page, 'currentPageSize': page_size, 'asyncColumns': 'client'},
        )

    def get_clients(
        self, site_id: str, active_only: bool = True, page: int = 1, page_size: int = 100
    ) -> dict:
        '''Raw clients page for one site (openapi/v2 clients search).
        Response shape unconfirmed, see module docstring - inspect the
        returned dict before relying on specific keys.
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

    def get_dashboard_overview(self, site_id: str) -> dict:
        '''Raw dashboard/card/overview for one site. Response shape
        unconfirmed, see module docstring.
        '''
        return self._get(f'/openapi/v1/{self._org_id}/sites/{site_id}/dashboard/card/overview')
