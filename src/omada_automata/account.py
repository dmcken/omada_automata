'''TP-Link Omada Cloud account: unified-ID SSO login, plus Cloud
Manager (account/organization) data.

Verified live against a real "Omada Essential" free-tier account via a
captured HAR of the id.tplinkcloud.com / omada-cloud web UI (one
organization, two sites, no MFA on the account). Auth flow, all under
*.tplinkcloud.com:

0. GET https://api-id.tplinkcloud.com/oauth/authorize
   ?clientId=omada-cloud-portal&redirectUri={redirect_uri}
   &responseType=code&state={state}&scope=openid
   -> 302 -> Location: https://id.tplinkcloud.com/#/login?session_code=...
   `state` is client-generated (the frontend's own opaque round-trip
   value - a random string here). This step is NOT optional, despite
   looking skippable at first glance (nothing in the login POST body
   below visibly references it): the `session_code` from this
   redirect's Location must be sent back as a `session_code` HTTP
   *header* (not body, not query string - easy to miss, and originally
   missed here) on the login POST in step 1, or step 3 fails with
   "[-52054] Account authentication code is invalid" - confirmed live
   both ways (with and without it). Without that header, the login
   POST still succeeds, but the server has no way to associate it with
   this specific pending OAuth request, so it silently falls back to
   some default/self-referential client instead of the one actually
   requested - `redirectParams` in step 1's response comes back for an
   entirely different, unusable client (`clientId=unified_id`) when the
   header is omitted, versus correctly echoing back `omada-cloud-portal`
   (this step 0's own clientId/redirectUri/responseType/scope/state)
   when it's included. `redirect_uri` here doesn't need to match the
   account's real region - it's just an opaque value the server
   round-trips back verbatim; the *real* region-correct redirect
   happens in step 2 against `serviceUrl`.

1. POST https://h2api-id.tplinkcloud.com/api/v1/login
   Header: session_code: {session_code from step 0}
   Body: {"email", "password", "terminalUUID", "privatePolicyChecked": false}
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
   This is the call that actually establishes the session - step 1's
   login POST sets `UID_SSO_SID`/`SESSION` cookies (confirmed live,
   despite the HAR this was built from having cookies stripped from
   every request/response - a devtools export quirk, not a gap in this
   implementation), and a plain `requests.Session()` carries them
   across every call below automatically. `csrfToken` must be sent
   back as the `Csrf-Token` header on every authenticated call from
   here on - confirmed to be the *same* token accepted by both Cloud
   Manager and a per-organization Essential Controller.

   cloud_manager_base for step 3 is never handed to the client by any
   prior response - the web UI derives it from serviceUrl's own
   hostname (swap the "api-id" segment for "api-omada-cloud-manager",
   same region prefix). That's inferred from the traffic pattern, not
   from a documented mapping - isolated in _guess_cloud_manager_base()
   so a region that breaks the assumption is easy to fix in one place.
   Once login-with-uid-code succeeds, its response's `regionUrl` is the
   authoritative value and is what every subsequent call actually uses.

MFA/2FA: not present in the originally captured login, but confirmed
live afterward against a real account with TOTP (authenticator app)
2FA enabled. Step 1's login POST responds the same way at the HTTP
level (200, JSON envelope) but with errorCode -20677 ("MFA feature
enabled") and a `result` of {"supportedMFATypes", "primaryMFAType",
"MFAEmail", "MFAProcessId"} instead of the usual accountId/serviceUrl/
redirectParams - login() raises exceptions.MfaRequired carrying this.
MFAEmail is present even though this account's primary (and only
configured) method is TOTP, not email - it looks like an
always-present account-level field rather than a signal of which
method is active, so it isn't reliable for choosing a method.

MFA verification is NOT a separate endpoint - reverse-engineered from
the login page's own JS bundle (id.tplinkcloud.com/js/index-*.js,
captured in the same HAR): it's the *exact same* step 1 login POST
(same URL, same session_code header, same email/password/terminalUUID/
privatePolicyChecked body), just with three extra body fields merged
in: {"needMfa": true, "mfaType": <primaryMFAType>, "code": <the 6-digit
code>, "mfaProcessId": <MFAProcessId from the MFA-required response>}.
On success this responds exactly like a normal step-1 success
(accountId/serviceUrl/redirectParams) and steps 2-3 proceed unchanged.
verify_mfa(code) does this, using state login() stashed from the
MFA-required response - the caller only needs to supply the code.
Confirmed live end-to-end for mfaType 3 (TOTP); other types are
unconfirmed (see exceptions.MfaRequired).

Logout - confirmed live, also under the regional unified-ID host from
step 1:

    POST {serviceUrl}/logout {"email", "clientId": "omada-cloud-portal"}
    -> {"errorCode": 0, "message": "OK"} (no "result" key at all).

Session caching: repeating the full 3-step login chain on every
process invocation (e.g. a monitoring job run every few minutes by
cron) is wasteful and adds load to TP-Link's identity service for no
benefit. get_session_state()/restore_session_state() let a caller
persist the session (cookies + CSRF token + derived hosts) between
process runs however they like (file, cache, env var - this module
doesn't pick for you) and skip login() entirely as long as
is_logged_in() still says the restored session is valid.
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
_GLOBAL_OAUTH_AUTHORIZE_URL = 'https://api-id.tplinkcloud.com/oauth/authorize'
_DEFAULT_REDIRECT_URI = 'https://use1-omada-cloud.tplinkcloud.com/#/loginRedirect'
_REDIRECT_STATUS_CODES = (301, 302, 303, 307, 308)
_MFA_REQUIRED_ERROR_CODE = -20677
MFA_TYPE_TOTP = 3


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


def _cookies_to_list(jar: requests.cookies.RequestsCookieJar) -> list[dict]:
    '''Serialize a cookie jar preserving domain/path/secure/expires -
    plain `requests.utils.dict_from_cookiejar` flattens to just
    name->value, which would silently break this SSO flow's
    domain-scoped cookies once restored (they need to be sent back to
    several different *.tplinkcloud.com subdomains, not just whichever
    host happened to set them).
    '''
    return [
        {
            'name': cookie.name,
            'value': cookie.value,
            'domain': cookie.domain,
            'path': cookie.path,
            'secure': cookie.secure,
            'expires': cookie.expires,
        }
        for cookie in jar
    ]


def _cookies_from_list(items: list[dict]) -> requests.cookies.RequestsCookieJar:
    '''Inverse of _cookies_to_list().'''
    jar = requests.cookies.RequestsCookieJar()
    for item in items:
        jar.set(
            item['name'],
            item['value'],
            domain=item.get('domain', ''),
            path=item.get('path', '/'),
            secure=item.get('secure', False),
            expires=item.get('expires'),
        )
    return jar


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
        self._id_service_url: str | None = None
        self._email: str | None = None
        self._pending_mfa: dict | None = None
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

    def _begin_oauth_session(self) -> str:
        '''Step 0 - GET the global oauth/authorize endpoint and return
        the session_code from its redirect. See the module docstring.
        '''
        try:
            resp = self._session.get(
                _GLOBAL_OAUTH_AUTHORIZE_URL,
                params={
                    'clientId': 'omada-cloud-portal',
                    'redirectUri': _DEFAULT_REDIRECT_URI,
                    'responseType': 'code',
                    'state': uuid.uuid4().hex[:6],
                    'scope': 'openid',
                },
                allow_redirects=False,
                timeout=self._timeout,
            )
        except (requests.exceptions.ConnectionError, requests.exceptions.ConnectTimeout) as exc:
            raise exceptions.AccountUnavailable("Could not reach the identity service") from exc
        if resp.status_code not in _REDIRECT_STATUS_CODES or 'Location' not in resp.headers:
            raise exceptions.AccountUnavailable(
                f"Initial oauth/authorize did not redirect as expected (status {resp.status_code})"
            )
        session_code = _parse_redirect_fragment(resp.headers['Location']).get('session_code')
        if not session_code:
            raise exceptions.AccountUnavailable(
                "Initial oauth/authorize redirect was missing session_code"
            )
        return session_code

    def _post_credentials(self, login_body: dict, session_code: str) -> dict:
        '''POST to step 1's login endpoint - used identically for the
        initial credential check and for verify_mfa()'s follow-up call
        (same endpoint, extra fields merged into `login_body`; see the
        module docstring). Checks transport/HTTP-level failures only -
        the caller decides what a non-zero errorCode means.
        '''
        try:
            resp = self._session.post(
                f"{_GLOBAL_ID_BASE}/api/v1/login",
                json=login_body,
                headers={'session_code': session_code},
                timeout=self._timeout,
            )
        except (requests.exceptions.ConnectionError, requests.exceptions.ConnectTimeout) as exc:
            raise exceptions.AccountUnavailable("Could not reach the identity service") from exc

        if resp.status_code != 200:
            raise exceptions.AccountUnavailable(
                f"Unexpected status {resp.status_code} logging in: {resp.text[:200]}"
            )
        return resp.json()

    def _complete_login(self, email: str, result: dict) -> None:
        '''Steps 2-3 - exchange step 1's result for a Cloud Manager
        session. Shared by login() and verify_mfa(), since a successful
        MFA verification responds identically to a successful plain
        login (see the module docstring).
        '''
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
        self._id_service_url = service_url
        self._email = email

    def login(self, email: str, password: str) -> None:
        '''Log in with the full unified-ID SSO chain described in the
        module docstring. On success, this account can call every
        Cloud Manager method below and mint EssentialController
        instances via essential_controller().

        Raises:
            exceptions.LoginFailed: Credentials rejected.
            exceptions.MfaRequired: Credentials were accepted but this
                account has 2FA enabled - call verify_mfa(code) with a
                fresh code to finish logging in.
            exceptions.AccountUnavailable: Couldn't reach the identity
                service, or the SSO hand-off didn't behave as captured
                (e.g. no redirect where one was expected).
        '''
        self._pending_mfa = None
        session_code = self._begin_oauth_session()
        login_body = {
            'email': email,
            'password': password,
            'terminalUUID': str(uuid.uuid4()),
            'privatePolicyChecked': False,
        }
        body = self._post_credentials(login_body, session_code)

        if body.get('errorCode') == _MFA_REQUIRED_ERROR_CODE:
            result = body.get('result') or {}
            self._pending_mfa = {
                'login_body': login_body,
                'session_code': session_code,
                'mfa_type': result.get('primaryMFAType'),
                'mfa_process_id': result.get('MFAProcessId'),
                'email': email,
            }
            raise exceptions.MfaRequired(
                mfa_type=result.get('primaryMFAType'),
                supported_mfa_types=result.get('supportedMFATypes', []),
                email=result.get('MFAEmail'),
            )

        if body.get('errorCode') != 0:
            logger.debug("Login rejected: %s", body.get('message'))
            raise exceptions.LoginFailed(body.get('message', 'login rejected'))

        self._complete_login(email, body['result'])

    def verify_mfa(self, code: str) -> None:
        '''Complete a login that raised exceptions.MfaRequired, by
        resubmitting the credential check with this code merged in -
        see the module docstring for why this isn't a separate
        endpoint. Only valid to call right after login() raised
        MfaRequired - the pending state (email/password/session_code/
        mfaProcessId) it stashed is cleared as soon as this succeeds or
        the login() that started it is retried.

        Raises:
            exceptions.AccountUnavailable: No pending MFA challenge
                (verify_mfa() called without a preceding login() that
                raised MfaRequired), or the identity service couldn't
                be reached.
            exceptions.LoginFailed: The code was rejected.
        '''
        if self._pending_mfa is None:
            raise exceptions.AccountUnavailable(
                "No pending MFA challenge - call login() first"
            )
        pending = self._pending_mfa

        body = self._post_credentials(
            {
                **pending['login_body'],
                'needMfa': True,
                'mfaType': pending['mfa_type'],
                'code': code,
                'mfaProcessId': pending['mfa_process_id'],
            },
            pending['session_code'],
        )

        if body.get('errorCode') != 0:
            logger.debug("MFA verification rejected: %s", body.get('message'))
            raise exceptions.LoginFailed(body.get('message', 'MFA verification rejected'))

        self._pending_mfa = None
        self._complete_login(pending['email'], body['result'])

    def logout(self) -> None:
        '''Log out of TP-Link Omada Cloud (POST {id_service_url}/logout)
        and clear this object's local session state, so it can't be
        mistaken for still being logged in afterwards - a subsequent
        is_logged_in() returns False without making a request, and any
        EssentialController obtained before logout() shares this same
        session/CSRF token, so it stops working too.

        Raises:
            exceptions.AccountUnavailable: Not currently logged in (no
                point logging out of nothing), or the identity service
                couldn't be reached.
            exceptions.ApiError: The logout call itself failed.
        '''
        if not self._id_service_url or not self._email:
            raise exceptions.AccountUnavailable("Not logged in - nothing to log out of")

        try:
            resp = self._session.post(
                f"{self._id_service_url}/logout",
                json={'email': self._email, 'clientId': 'omada-cloud-portal'},
                timeout=self._timeout,
            )
        except (requests.exceptions.ConnectionError, requests.exceptions.ConnectTimeout) as exc:
            raise exceptions.AccountUnavailable("Could not reach the identity service") from exc

        _envelope.unwrap(resp, 'logout')

        self._session = requests.Session()
        self._csrf_token = None
        self._cloud_manager_base = None
        self._id_service_url = None
        self._email = None
        self.account_id = None

    def is_logged_in(self) -> bool:
        '''Cheap check for whether this account's current session
        (freshly logged in, or restored via restore_session_state()) is
        still valid - hits Cloud Manager's own login-status endpoint,
        which reports {"login": false} rather than erroring once a
        session has expired server-side, instead of just assuming a
        restored session is good because it deserialized cleanly.

        Returns:
            bool: False if login() was never called (or logout() was),
                the session has expired, or the identity service can't
                be reached at all - True otherwise.
        '''
        if not self._cloud_manager_base:
            return False
        try:
            result = self._get('/api/v1/central/account/login-status')
        except (exceptions.ApiError, requests.exceptions.RequestException):
            return False
        return bool(result.get('login', False))

    def get_session_state(self) -> dict:
        '''Serializable snapshot of this account's session - cookies
        plus the bits login() derives (CSRF token, regional hosts,
        account id, email). Pass to restore_session_state() on a fresh
        OmadaCloudAccount to skip repeating the full SSO login chain
        across process runs (e.g. a monitoring job invoked on a
        schedule) - see the module docstring for the caching pattern
        this supports. Storage is entirely up to the caller (file,
        cache, secrets manager, ...); this only produces/consumes a
        plain JSON-serializable dict.
        '''
        return {
            'cookies': _cookies_to_list(self._session.cookies),
            'csrf_token': self._csrf_token,
            'cloud_manager_base': self._cloud_manager_base,
            'id_service_url': self._id_service_url,
            'account_id': self.account_id,
            'email': self._email,
        }

    def restore_session_state(self, state: dict) -> None:
        '''Restore a session captured by get_session_state(), on a
        fresh (not yet logged in) OmadaCloudAccount. Does not itself
        verify the session is still valid server-side - call
        is_logged_in() afterwards and fall back to login() if it
        returns False (the session cookies/CSRF token can simply have
        expired since the state was captured).
        '''
        self._session.cookies.update(_cookies_from_list(state.get('cookies', [])))
        self._csrf_token = state.get('csrf_token')
        self._cloud_manager_base = state.get('cloud_manager_base')
        self._id_service_url = state.get('id_service_url')
        self.account_id = state.get('account_id')
        self._email = state.get('email')

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
            redirect_url=api_url.get('redirectUrl'),
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
            frontend_origin=hosts.redirect_url,
            timeout=self._timeout,
        )
