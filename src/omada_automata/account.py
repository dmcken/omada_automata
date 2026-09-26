'''TP-Link Omada Cloud account: unified-ID SSO login, plus Cloud
Manager (account/organization) data.

Verified live against a real "Omada Essential" free-tier account via a
captured HAR of the id.tplinkcloud.com / omada-cloud web UI (one
organization, two sites, no MFA on the account). Auth flow, all under
*.tplinkcloud.com:

1. POST https://h2api-id.tplinkcloud.com/api/v1/login
   {"email", "password", "terminalUUID", "privatePolicyChecked": false}
   -> {"result": {"accountId", "serviceUrl", "redirectParams"}}.
   `serviceUrl` is this account's *regional* unified-ID host (e.g.
   "https://use1-api-id.tplinkcloud.com") - h2api-id.tplinkcloud.com is
   only a global entry point for the credential check itself; every
   step after this is scoped to that region. terminalUUID looks like a
   per-browser device fingerprint (localStorage-persisted client side)
   - generating a fresh random one per login was not cross-checked
   against a second real login, but nothing observed suggests the
   server pins it to a previously-seen value.

2. GET {serviceUrl}/oauth/authorize?{redirectParams} -> 302, whose
   Location header is a frontend SPA route carrying `code`/`state`
   query params after a `#` fragment - this is never actually a page
   navigation, just how the frontend receives an OAuth-style
   authorization code from an endpoint that happens to speak redirects.

3. POST {cloud_manager_base}/api/v1/central/account/login-with-uid-code
   {"code", "state", "uidServiceUrl": serviceUrl, "canary": true}
   -> {"result": {"csrfToken", "regionUrl", "redirectUrl"}}.
   This is the call that actually establishes the session. The HAR
   this was built from had cookies stripped from every request/response
   (a devtools export quirk, not something this code can see around) -
   but a plain `requests.Session()` carries whatever cookies the server
   actually sets across every call below regardless of whether a HAR
   viewer chose to display them, so this isn't a gap in the
   implementation, just in what could be directly confirmed from the
   capture. `csrfToken` must be sent back as the `Csrf-Token` header on
   every authenticated call from here on - confirmed to be the *same*
   token accepted by both Cloud Manager and a per-organization
   Essential Controller.

   cloud_manager_base for step 3 is never handed to the client by any
   prior response - the web UI derives it from serviceUrl's own
   hostname (swap the "api-id" segment for "api-omada-cloud-manager",
   same region prefix). That's inferred from the traffic pattern, not
   from a documented mapping - isolated in _guess_cloud_manager_base()
   so a region that breaks the assumption is easy to fix in one place.
   Once login-with-uid-code succeeds, its response's `regionUrl` is the
   authoritative value and is what every subsequent call actually uses.

No MFA/2FA step was present in the captured login. An account with
MFA enabled will hit a different flow that hasn't been observed - this
module doesn't attempt to handle it.
'''
from __future__ import annotations

import logging
import urllib.parse
import uuid

import requests

from . import _envelope, exceptions, models
from .essential import EssentialController

logger = logging.getLogger(__name__)

_GLOBAL_ID_BASE = 'https://h2api-id.tplinkcloud.com'
_REDIRECT_STATUS_CODES = (301, 302, 303, 307, 308)


def _guess_cloud_manager_base(service_url: str) -> str:
    '''Derive the Cloud Manager base URL from the regional unified-ID
    host returned by step 1 - see the module docstring for why this is
    a guess rather than something an API response hands us directly.
    '''
    host = urllib.parse.urlsplit(service_url).netloc
    suffix = '-api-id.tplinkcloud.com'
    if not host.endswith(suffix):
        raise exceptions.AccountUnavailable(
            f"Unrecognized unified-ID host format, can't derive Cloud Manager host: {host}"
        )
    region = host[: -len(suffix)]
    return f"https://{region}-api-omada-cloud-manager.tplinkcloud.com"


def _parse_redirect_fragment(location: str) -> dict[str, str]:
    '''Pull the query params out of an oauth/authorize redirect's
    Location header - they live after a `#/route` fragment, not in the
    URL's own query string.
    '''
    fragment = urllib.parse.urlsplit(location).fragment
    _, _, query = fragment.partition('?')
    return dict(urllib.parse.parse_qsl(query))


def _parse_organization(data: dict) -> models.Organization:
    return models.Organization(
        org_id=data['orgId'],
        name=data.get('name', ''),
        category=data.get('category', ''),
        site_num=data.get('siteNum', 0),
        role=data.get('role', 0),
        msp_mode=data.get('mspMode', False),
        central_enable=data.get('centralEnable', False),
        network_enable=data.get('networkEnable', False),
        surveillance_enable=data.get('surveillanceEnable', False),
    )


class OmadaCloudAccount:
    '''A logged-in TP-Link Omada Cloud account. Get a per-organization
    controller via essential_controller(org_id) once logged in.
    '''

    _default_timeout = 30

    def __init__(self, timeout: int | None = None) -> None:
        self._timeout = timeout if timeout is not None else self._default_timeout
        self._session = requests.Session()
        self._csrf_token: str | None = None
        self._cloud_manager_base: str | None = None
        self.account_id: str | None = None

    def _headers(self) -> dict:
        headers = {'X-Requested-With': 'XMLHttpRequest'}
        if self._csrf_token:
            headers['Csrf-Token'] = self._csrf_token
        return headers

    def _get(self, path: str, params: dict | None = None):
        resp = self._session.get(
            f"{self._cloud_manager_base}{path}",
            params=params,
            headers=self._headers(),
            timeout=self._timeout,
        )
        return _envelope.unwrap(resp, path)

    def _post(self, path: str, json_body: dict | None = None):
        resp = self._session.post(
            f"{self._cloud_manager_base}{path}",
            json=json_body,
            headers=self._headers(),
            timeout=self._timeout,
        )
        return _envelope.unwrap(resp, path)

    def login(self, email: str, password: str) -> None:
        '''Log in with the full unified-ID SSO chain described in the
        module docstring. On success, this account can call every
        Cloud Manager method below and mint EssentialController
        instances via essential_controller().

        Raises:
            exceptions.LoginFailed: Credentials rejected.
            exceptions.AccountUnavailable: Couldn't reach the identity
                service, or the SSO hand-off didn't behave as captured
                (e.g. no redirect where one was expected).
        '''
        try:
            resp = self._session.post(
                f"{_GLOBAL_ID_BASE}/api/v1/login",
                json={
                    'email': email,
                    'password': password,
                    'terminalUUID': str(uuid.uuid4()),
                    'privatePolicyChecked': False,
                },
                timeout=self._timeout,
            )
        except (requests.exceptions.ConnectionError, requests.exceptions.ConnectTimeout) as exc:
            raise exceptions.AccountUnavailable("Could not reach the identity service") from exc

        if resp.status_code != 200:
            raise exceptions.AccountUnavailable(
                f"Unexpected status {resp.status_code} logging in: {resp.text[:200]}"
            )

        body = resp.json()
        if body.get('errorCode') != 0:
            logger.debug("Login rejected: %s", body.get('message'))
            raise exceptions.LoginFailed(body.get('message', 'login rejected'))

        result = body['result']
        self.account_id = result['accountId']
        service_url = result['serviceUrl']

        resp = self._session.get(
            f"{service_url}/oauth/authorize?{result['redirectParams']}",
            allow_redirects=False,
            timeout=self._timeout,
        )
        if resp.status_code not in _REDIRECT_STATUS_CODES or 'Location' not in resp.headers:
            raise exceptions.AccountUnavailable(
                f"oauth/authorize did not redirect as expected (status {resp.status_code})"
            )
        redirect_params = _parse_redirect_fragment(resp.headers['Location'])
        if 'code' not in redirect_params or 'state' not in redirect_params:
            raise exceptions.AccountUnavailable(
                "oauth/authorize redirect was missing code/state"
            )

        cloud_manager_base = _guess_cloud_manager_base(service_url)
        resp = self._session.post(
            f"{cloud_manager_base}/api/v1/central/account/login-with-uid-code",
            json={
                'code': redirect_params['code'],
                'state': redirect_params['state'],
                'uidServiceUrl': service_url,
                'canary': True,
            },
            headers=self._headers(),
            timeout=self._timeout,
        )
        result = _envelope.unwrap(resp, 'login-with-uid-code')
        self._csrf_token = result['csrfToken']
        self._cloud_manager_base = result.get('regionUrl', cloud_manager_base)

    def get_account_detail(self) -> dict:
        '''Raw account/detail - username/nickname/email/accountId/region.'''
        return self._get('/api/v1/central/account/detail')

    def list_organizations(self) -> list[models.Organization]:
        '''List every organization (account/organization-list) this
        account has access to.
        '''
        result = self._get(
            '/api/v1/central/account/organization-list',
            params={'currentPage': 1, 'currentPageSize': 100, 'filters.type': 3},
        )
        return [_parse_organization(o) for o in result.get('data', [])]

    def get_organization(self, org_id: str) -> dict:
        '''Raw organizations/{org_id} - name/region/timeZone/category/
        networkVersion/surveillanceVersion.
        '''
        return self._get(
            f'/api/v1/central/account/organizations/{org_id}',
            params={'regionType': 1},
        )

    def get_hosts(self, org_id: str) -> models.OrganizationHosts:
        '''This organization's per-product regional API base URLs
        (account/central/{org_id}/hosts) - used internally by
        essential_controller(), exposed directly in case a caller needs
        the Central or Omada (classic-branding) base URL too.
        '''
        result = self._get(
            f'/api/v1/central/account/central/{org_id}/hosts',
            params={'regionType': 1},
        )
        api_url = result.get('apiUrl', {})
        return models.OrganizationHosts(
            omada=api_url.get('omada'),
            essential=api_url.get('essential'),
            central=api_url.get('central'),
            vms=api_url.get('vms'),
        )

    def essential_controller(self, org_id: str) -> EssentialController:
        '''Get an EssentialController bound to one organization -
        looks up that organization's Essential Controller base URL via
        get_hosts() and reuses this account's session/CSRF token.

        Raises:
            exceptions.ApiError: This organization has no Essential
                Controller (e.g. Central-only or Omada-classic-only
                organization).
        '''
        hosts = self.get_hosts(org_id)
        if not hosts.essential:
            raise exceptions.ApiError(
                -1, "Organization has no Essential Controller", f'hosts({org_id})'
            )
        return EssentialController(
            session=self._session,
            org_id=org_id,
            base_url=hosts.essential,
            csrf_token=self._csrf_token,
            timeout=self._timeout,
        )
