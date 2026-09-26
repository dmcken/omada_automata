'''Tests for OmadaCloudAccount - the unified-ID SSO login chain and
Cloud Manager (account/organization) endpoints.'''
import pytest

from omada_automata import exceptions
from omada_automata.account import (
    OmadaCloudAccount,
    _guess_cloud_manager_base,
    _parse_redirect_fragment,
)


class TestGuessCloudManagerBase:
    def test_swaps_api_id_for_api_omada_cloud_manager(self):
        assert (
            _guess_cloud_manager_base('https://use1-api-id.tplinkcloud.com')
            == 'https://use1-api-omada-cloud-manager.tplinkcloud.com'
        )

    def test_unrecognized_host_raises(self):
        with pytest.raises(exceptions.AccountUnavailable):
            _guess_cloud_manager_base('https://not-the-expected-shape.example.com')


class TestParseRedirectFragment:
    def test_extracts_code_and_state_from_fragment_query(self):
        location = (
            'https://use1-omada-cloud.tplinkcloud.com/#/loginRedirect'
            '?code=abc123&state=xyz&serviceUrl=https%3A%2F%2Fuse1-api-id.tplinkcloud.com&canary=true'
        )
        params = _parse_redirect_fragment(location)
        assert params['code'] == 'abc123'
        assert params['state'] == 'xyz'


def _mock_login_chain(requests_mock, *, login_error_code=0, oauth_status=302):
    requests_mock.post(
        'https://h2api-id.tplinkcloud.com/api/v1/login',
        json={
            'errorCode': login_error_code,
            'message': 'OK' if login_error_code == 0 else 'wrong password',
            'result': {
                'redirectParams': 'responseType=code&clientId=x&state=wee6ki',
                'accountId': '12345',
                'serviceUrl': 'https://use1-api-id.tplinkcloud.com',
            },
        },
    )
    requests_mock.get(
        'https://use1-api-id.tplinkcloud.com/oauth/authorize',
        status_code=oauth_status,
        headers={
            'Location': (
                'https://use1-omada-cloud.tplinkcloud.com/#/loginRedirect'
                '?code=JEZbXk&state=wee6ki&serviceUrl=https%3A%2F%2Fuse1-api-id.tplinkcloud.com'
            ),
        } if oauth_status in (301, 302, 303, 307, 308) else {},
    )
    requests_mock.post(
        'https://use1-api-omada-cloud-manager.tplinkcloud.com/api/v1/central/account/login-with-uid-code',
        json={
            'errorCode': 0,
            'msg': 'OK',
            'result': {
                'csrfToken': 'fake-csrf-token',
                'regionUrl': 'https://use1-api-omada-cloud-manager.tplinkcloud.com',
                'redirectUrl': 'https://use1-omada-cloud.tplinkcloud.com',
            },
        },
    )


class TestLogin:
    def test_success_stores_csrf_token_and_account_id(self, requests_mock):
        _mock_login_chain(requests_mock)
        account = OmadaCloudAccount()

        account.login('test.user@example.com', 'fake-password')

        assert account.account_id == '12345'
        assert account._csrf_token == 'fake-csrf-token'
        assert account._cloud_manager_base == 'https://use1-api-omada-cloud-manager.tplinkcloud.com'

    def test_sends_credentials_in_login_body(self, requests_mock):
        _mock_login_chain(requests_mock)
        account = OmadaCloudAccount()

        account.login('test.user@example.com', 'fake-password')

        sent = requests_mock.request_history[0].json()
        assert sent['email'] == 'test.user@example.com'
        assert sent['password'] == 'fake-password'

    def test_rejected_credentials_raise_login_failed(self, requests_mock):
        _mock_login_chain(requests_mock, login_error_code=1)
        account = OmadaCloudAccount()

        with pytest.raises(exceptions.LoginFailed):
            account.login('test.user@example.com', 'wrong-password')

    def test_password_never_appears_in_logs(self, requests_mock, caplog):
        _mock_login_chain(requests_mock, login_error_code=1)
        account = OmadaCloudAccount()

        with caplog.at_level('DEBUG'):
            with pytest.raises(exceptions.LoginFailed):
                account.login('test.user@example.com', 'super-secret-password')

        assert 'super-secret-password' not in caplog.text

    def test_missing_oauth_redirect_raises_account_unavailable(self, requests_mock):
        _mock_login_chain(requests_mock, oauth_status=200)
        account = OmadaCloudAccount()

        with pytest.raises(exceptions.AccountUnavailable):
            account.login('test.user@example.com', 'fake-password')

    def test_connection_error_raises_account_unavailable(self, requests_mock):
        import requests as requests_lib
        requests_mock.post(
            'https://h2api-id.tplinkcloud.com/api/v1/login',
            exc=requests_lib.exceptions.ConnectionError,
        )
        account = OmadaCloudAccount()

        with pytest.raises(exceptions.AccountUnavailable):
            account.login('test.user@example.com', 'fake-password')


class _LoggedInAccount(OmadaCloudAccount):
    '''Test helper: an account that's already past login(), so tests
    for the Cloud Manager methods don't have to re-run the whole SSO
    chain.'''
    def __init__(self):
        super().__init__()
        self._csrf_token = 'fake-csrf-token'
        self._cloud_manager_base = 'https://use1-api-omada-cloud-manager.tplinkcloud.com'
        self.account_id = '12345'


class TestListOrganizations:
    def test_parses_organization_fields(self, requests_mock, load_json):
        requests_mock.get(
            'https://use1-api-omada-cloud-manager.tplinkcloud.com/api/v1/central/account/organization-list',
            json=load_json('organization_list.json'),
        )
        account = _LoggedInAccount()

        orgs = account.list_organizations()

        assert len(orgs) == 1
        assert orgs[0].org_id == '0000000000000000000000000000000'
        assert orgs[0].name == 'Test Organization'
        assert orgs[0].site_num == 2
        assert orgs[0].network_enable is True

    def test_sends_csrf_token_header(self, requests_mock, load_json):
        requests_mock.get(
            'https://use1-api-omada-cloud-manager.tplinkcloud.com/api/v1/central/account/organization-list',
            json=load_json('organization_list.json'),
        )
        account = _LoggedInAccount()

        account.list_organizations()

        assert requests_mock.request_history[0].headers['Csrf-Token'] == 'fake-csrf-token'


class TestGetHosts:
    def test_parses_per_product_urls(self, requests_mock, load_json):
        requests_mock.get(
            'https://use1-api-omada-cloud-manager.tplinkcloud.com'
            '/api/v1/central/account/central/0000000000000000000000000000000/hosts',
            json=load_json('organization_hosts.json'),
        )
        account = _LoggedInAccount()

        hosts = account.get_hosts('0000000000000000000000000000000')

        assert hosts.essential == 'https://use1-api-omada-essential-controller.tplinkcloud.com'
        assert hosts.central == 'https://use1-api-omada-central.tplinkcloud.com'


class TestEssentialController:
    def test_builds_controller_with_essential_host(self, requests_mock, load_json):
        requests_mock.get(
            'https://use1-api-omada-cloud-manager.tplinkcloud.com'
            '/api/v1/central/account/central/0000000000000000000000000000000/hosts',
            json=load_json('organization_hosts.json'),
        )
        account = _LoggedInAccount()

        controller = account.essential_controller('0000000000000000000000000000000')

        assert controller._base_url == 'https://use1-api-omada-essential-controller.tplinkcloud.com'
        assert controller._org_id == '0000000000000000000000000000000'
        assert controller._csrf_token == 'fake-csrf-token'

    def test_no_essential_host_raises_api_error(self, requests_mock):
        requests_mock.get(
            'https://use1-api-omada-cloud-manager.tplinkcloud.com'
            '/api/v1/central/account/central/0000000000000000000000000000000/hosts',
            json={'errorCode': 0, 'msg': 'OK', 'result': {'apiUrl': {'central': 'https://x'}}},
        )
        account = _LoggedInAccount()

        with pytest.raises(exceptions.ApiError):
            account.essential_controller('0000000000000000000000000000000')


class TestEnvelopeErrors:
    def test_non_zero_error_code_raises_api_error(self, requests_mock):
        requests_mock.get(
            'https://use1-api-omada-cloud-manager.tplinkcloud.com/api/v1/central/account/detail',
            json={'errorCode': -1, 'msg': 'Not logged in', 'result': None},
        )
        account = _LoggedInAccount()

        with pytest.raises(exceptions.ApiError):
            account.get_account_detail()

    def test_non_200_raises_api_error(self, requests_mock):
        requests_mock.get(
            'https://use1-api-omada-cloud-manager.tplinkcloud.com/api/v1/central/account/detail',
            status_code=500,
            text='error',
        )
        account = _LoggedInAccount()

        with pytest.raises(exceptions.ApiError):
            account.get_account_detail()
