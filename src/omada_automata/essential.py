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

from . import _envelope, exceptions, models

logger = logging.getLogger(__name__)

_CONTROLLER_WAKING_UP_ERROR_CODE = -1200
_WAKEUP_RETRY_DELAYS_SECONDS = (2, 5, 10)


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
