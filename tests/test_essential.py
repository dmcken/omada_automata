'''Tests for EssentialController - the per-organization site
controller (sites/devices/clients/alerts).'''
import base64
import typing
import uuid

import pytest
import requests

from omada_automata import exceptions
from omada_automata.essential import EssentialController

BASE_URL = 'https://use1-api-omada-essential-controller.tplinkcloud.com'
ORG_ID = '0000000000000000000000000000000'
SITE_ID = 'site-1'
DEVICE_MAC = 'AA-BB-CC-DD-EE-FF'
_FIXED_UUID = uuid.UUID('11111111-1111-1111-1111-111111111111')
_FIXED_NID = _FIXED_UUID.hex


def _b64(text: str) -> str:
    return base64.b64encode(text.encode()).decode()


def _controller():
    '''A controller with Shiro priming already marked done, so tests
    for individual data methods don't also have to mock
    current/login-status - see TestShiroLoginPriming for that.'''
    controller = EssentialController(
        session=requests.Session(),
        org_id=ORG_ID,
        base_url=BASE_URL,
        csrf_token='fake-csrf-token',
    )
    controller._shiro_login_done = True
    return controller


class TestHeaders:
    def test_includes_csrf_token(self):
        controller = _controller()
        assert controller._headers()['Csrf-Token'] == 'fake-csrf-token'

    def test_no_csrf_token_omits_header(self):
        controller = EssentialController(
            session=requests.Session(), org_id=ORG_ID, base_url=BASE_URL, csrf_token=None,
        )
        assert 'Csrf-Token' not in controller._headers()


class TestShiroLoginPriming:
    '''current/login-status?needToken=true must be called once before
    any other endpoint works, confirmed live - see the module
    docstring. A fresh EssentialController (not the `_controller()`
    helper, which pre-marks this done) exercises that priming call.'''

    def _fresh_controller(self):
        return EssentialController(
            session=requests.Session(),
            org_id=ORG_ID,
            base_url=BASE_URL,
            csrf_token='fake-csrf-token',
        )

    def test_primes_before_the_first_data_call(self, requests_mock):
        requests_mock.get(
            f'{BASE_URL}/{ORG_ID}/api/v2/current/login-status',
            json={'errorCode': 0, 'msg': 'OK', 'result': {'needShiroLogin': True}},
        )
        requests_mock.get(
            f'{BASE_URL}/{ORG_ID}/api/v2/organization/site-ids',
            json={'errorCode': 0, 'msg': 'Success.', 'result': {'siteIds': ['a']}},
        )
        controller = self._fresh_controller()

        result = controller.get_site_ids()

        assert result == ['a']
        methods_and_paths = [(r.method, r.path) for r in requests_mock.request_history]
        assert methods_and_paths == [
            ('GET', f'/{ORG_ID}/api/v2/current/login-status'),
            ('GET', f'/{ORG_ID}/api/v2/organization/site-ids'),
        ]

    def test_only_primes_once_per_instance(self, requests_mock):
        requests_mock.get(
            f'{BASE_URL}/{ORG_ID}/api/v2/current/login-status',
            json={'errorCode': 0, 'msg': 'OK', 'result': {}},
        )
        requests_mock.get(
            f'{BASE_URL}/{ORG_ID}/api/v2/organization/site-ids',
            json={'errorCode': 0, 'msg': 'Success.', 'result': {'siteIds': []}},
        )
        controller = self._fresh_controller()

        controller.get_site_ids()
        controller.get_site_ids()

        login_status_calls = [
            r for r in requests_mock.request_history
            if r.path == f'/{ORG_ID}/api/v2/current/login-status'
        ]
        assert len(login_status_calls) == 1

    def test_priming_failure_propagates(self, requests_mock):
        requests_mock.get(
            f'{BASE_URL}/{ORG_ID}/api/v2/current/login-status',
            json={'errorCode': -1, 'msg': 'not logged in'},
        )
        controller = self._fresh_controller()

        with pytest.raises(exceptions.ApiError):
            controller.get_site_ids()


class TestGetSites:
    def test_parses_site_fields(self, requests_mock, load_json):
        requests_mock.get(
            f'{BASE_URL}/{ORG_ID}/api/v2/user/sites',
            json=load_json('user_sites.json'),
        )
        controller = _controller()

        sites = controller.get_sites()

        assert len(sites) == 2
        assert sites[0].site_id == 'aaaaaaaaaaaaaaaaaaaaaaaa'
        assert sites[0].name == 'Test Site One'
        assert sites[0].favorite is False

    def test_sends_csrf_token_header(self, requests_mock, load_json):
        requests_mock.get(
            f'{BASE_URL}/{ORG_ID}/api/v2/user/sites',
            json=load_json('user_sites.json'),
        )
        controller = _controller()

        controller.get_sites()

        assert requests_mock.request_history[0].headers['Csrf-Token'] == 'fake-csrf-token'


class TestGetSiteIds:
    def test_returns_id_list(self, requests_mock):
        requests_mock.get(
            f'{BASE_URL}/{ORG_ID}/api/v2/organization/site-ids',
            json={'errorCode': 0, 'msg': 'Success.', 'result': {'siteIds': ['a', 'b']}},
        )
        controller = _controller()

        assert controller.get_site_ids() == ['a', 'b']


class TestGetCurrentUser:
    def test_parses_identity_and_site_privilege(self, requests_mock, load_json):
        requests_mock.get(
            f'{BASE_URL}/{ORG_ID}/api/v2/current/user-detail',
            json=load_json('current_user_detail.json'),
        )
        controller = _controller()

        user = controller.get_current_user()

        assert user.email == 'test.user@example.com'
        assert user.role_name == 'Super Admin'
        assert user.site_privilege.all_sites is True
        assert user.site_privilege.site_ids == [
            'aaaaaaaaaaaaaaaaaaaaaaaa', 'bbbbbbbbbbbbbbbbbbbbbbbb',
        ]


class TestGetAlertCount:
    def test_returns_alert_num(self, requests_mock):
        requests_mock.get(
            f'{BASE_URL}/{ORG_ID}/api/v2/sites/site-1/site/alerts/num',
            json={'errorCode': 0, 'msg': 'Success.', 'result': {'alertNum': 3}},
        )
        controller = _controller()

        assert controller.get_alert_count('site-1') == 3


class TestGetDevices:
    def test_sends_expected_query_params(self, requests_mock):
        requests_mock.get(
            f'{BASE_URL}/{ORG_ID}/api/v2/sites/site-1/grid/devices',
            json={'errorCode': 0, 'msg': 'Success.', 'result': {'data': []}},
        )
        controller = _controller()

        controller.get_devices('site-1', page=2, page_size=25)

        query = requests_mock.request_history[0].qs
        assert query['currentpage'] == ['2']
        assert query['currentpagesize'] == ['25']
        assert query['asynccolumns'] == ['client']

    def test_non_zero_error_code_raises(self, requests_mock):
        requests_mock.get(
            f'{BASE_URL}/{ORG_ID}/api/v2/sites/site-1/grid/devices',
            json={'errorCode': -1, 'msg': 'boom', 'result': None},
        )
        controller = _controller()

        with pytest.raises(exceptions.ApiError):
            controller.get_devices('site-1')


class TestGetClients:
    def test_sends_expected_body(self, requests_mock):
        requests_mock.post(
            f'{BASE_URL}/openapi/v2/{ORG_ID}/sites/site-1/clients',
            json={'errorCode': 0, 'msg': 'Success.', 'result': {'data': []}},
        )
        controller = _controller()

        controller.get_clients('site-1', active_only=True, page=1, page_size=10)

        sent = requests_mock.request_history[0].json()
        assert sent == {
            'filters': {'active': True}, 'sorts': {}, 'page': 1, 'pageSize': 10, 'scope': 1,
        }


class TestGetDashboardOverview:
    def test_uses_openapi_v1_path(self, requests_mock):
        requests_mock.get(
            f'{BASE_URL}/openapi/v1/{ORG_ID}/sites/site-1/dashboard/card/overview',
            json={'errorCode': 0, 'msg': 'Success.', 'result': {'onlineDevices': 5}},
        )
        controller = _controller()

        result = controller.get_dashboard_overview('site-1')

        assert result == {'onlineDevices': 5}


class TestControllerWakingUpRetry:
    '''errorCode -1200 ("logged out of the controller ... try to log in
    again later") is confirmed live on the first real data call after a
    fresh login against a free-tier organization - the controller
    appears to need a few seconds to spin up. _get()/_post() retry a
    few times with backoff on this specific error before giving up.'''

    def test_retries_and_succeeds_after_transient_wakeup_error(self, requests_mock, monkeypatch):
        sleeps = []
        monkeypatch.setattr('time.sleep', sleeps.append)
        requests_mock.get(
            f'{BASE_URL}/{ORG_ID}/api/v2/organization/site-ids',
            [
                {'json': {'errorCode': -1200, 'msg': 'logged out of the controller'}},
                {'json': {'errorCode': -1200, 'msg': 'logged out of the controller'}},
                {'json': {'errorCode': 0, 'msg': 'Success.', 'result': {'siteIds': ['a']}}},
            ],
        )
        controller = _controller()

        result = controller.get_site_ids()

        assert result == ['a']
        assert len(sleeps) == 2  # two failed attempts before the third succeeded
        assert sleeps == [2, 5]

    def test_gives_up_after_exhausting_retries(self, requests_mock, monkeypatch):
        monkeypatch.setattr('time.sleep', lambda _seconds: None)
        requests_mock.get(
            f'{BASE_URL}/{ORG_ID}/api/v2/organization/site-ids',
            json={'errorCode': -1200, 'msg': 'still logged out of the controller'},
        )
        controller = _controller()

        with pytest.raises(exceptions.ApiError) as exc_info:
            controller.get_site_ids()

        assert exc_info.value.error_code == -1200

    def test_other_error_codes_are_not_retried(self, requests_mock, monkeypatch):
        sleeps = []
        monkeypatch.setattr('time.sleep', sleeps.append)
        requests_mock.get(
            f'{BASE_URL}/{ORG_ID}/api/v2/organization/site-ids',
            json={'errorCode': -1, 'msg': 'some other failure'},
        )
        controller = _controller()

        with pytest.raises(exceptions.ApiError) as exc_info:
            controller.get_site_ids()

        assert exc_info.value.error_code == -1
        assert sleeps == []


class _FakeSockJsStompClient:
    '''Stand-in for _sockjs_stomp.SockJsStompClient - the real one
    opens an actual WebSocket in its constructor, so network-check
    tests monkeypatch this in instead. Subclass and set `messages` to
    control what iter_messages() yields.
    '''
    last_instance = None
    messages: typing.ClassVar[list] = []

    def __init__(self, ws_url, origin, cookie_header, csrf_token, timeout):
        self.ws_url = ws_url
        self.origin = origin
        self.cookie_header = cookie_header
        self.csrf_token = csrf_token
        self.timeout = timeout
        self.subscribed = []
        self.closed = False
        type(self).last_instance = self

    def subscribe(self, destination):
        self.subscribed.append(destination)
        return 'fake-sub-id'

    def iter_messages(self, idle_timeout=None):
        yield from self.messages

    def close(self):
        self.closed = True


def _install_fake_ws_client(monkeypatch, messages):
    fake_class = type('FakeSockJsStompClient', (_FakeSockJsStompClient,), {'messages': messages})
    monkeypatch.setattr('omada_automata._sockjs_stomp.SockJsStompClient', fake_class)
    monkeypatch.setattr('omada_automata.essential.uuid.uuid4', lambda: _FIXED_UUID)
    return fake_class


def _ack_response(mac=DEVICE_MAC, error_code=0):
    return {
        'errorCode': 0,
        'msg': 'Success.',
        'result': {'deviceResult': [{'errorCode': error_code, 'mac': mac, 'nid': _FIXED_NID}]},
    }


def _troubleshooting_message(mac, seq, text, finish):
    return {
        'type': 'troubleshootingTest',
        'data': {'nid': _FIXED_NID, 'mac': mac, 'seq': seq, 'msg': _b64(text), 'finish': finish},
    }


class TestPing:
    def test_sends_expected_body_and_decodes_output(self, requests_mock, monkeypatch):
        fake_class = _install_fake_ws_client(monkeypatch, [
            _troubleshooting_message(DEVICE_MAC, 0, 'PING 8.8.8.8, 32 data bytes.\n', False),
            _troubleshooting_message(DEVICE_MAC, 1, 'Reply from 8.8.8.8: time=58ms\n', True),
        ])
        requests_mock.post(
            f'{BASE_URL}/{ORG_ID}/api/v2/sites/{SITE_ID}/tools/network-check/0',
            json=_ack_response(),
        )
        controller = _controller()

        result = controller.ping(SITE_ID, [DEVICE_MAC], dest='8.8.8.8')

        assert result == {
            DEVICE_MAC: 'PING 8.8.8.8, 32 data bytes.\nReply from 8.8.8.8: time=58ms\n',
        }
        sent = requests_mock.request_history[-1].json()
        assert sent == {
            'deviceType': 0,
            'source': [DEVICE_MAC],
            'nid': _FIXED_NID,
            'destType': 0,
            'dest': '8.8.8.8',
            'packetSize': 32,
            'count': 4,
        }
        assert fake_class.last_instance.subscribed == [
            f'/user/queue/ws/{ORG_ID}/sites/{SITE_ID}/status'
        ]
        assert fake_class.last_instance.closed is True

    def test_client_target_uses_client_field(self, requests_mock, monkeypatch):
        _install_fake_ws_client(monkeypatch, [
            _troubleshooting_message(DEVICE_MAC, 0, 'ok\n', True),
        ])
        requests_mock.post(
            f'{BASE_URL}/{ORG_ID}/api/v2/sites/{SITE_ID}/tools/network-check/0',
            json=_ack_response(),
        )
        controller = _controller()

        controller.ping(SITE_ID, [DEVICE_MAC], dest_client_mac='11-22-33-44-55-66')

        sent = requests_mock.request_history[-1].json()
        assert sent['destType'] == 1
        assert sent['client'] == '11-22-33-44-55-66'
        assert 'dest' not in sent

    def test_device_error_raises_api_error(self, requests_mock, monkeypatch):
        _install_fake_ws_client(monkeypatch, [])
        requests_mock.post(
            f'{BASE_URL}/{ORG_ID}/api/v2/sites/{SITE_ID}/tools/network-check/0',
            json=_ack_response(error_code=-1),
        )
        controller = _controller()

        with pytest.raises(exceptions.ApiError):
            controller.ping(SITE_ID, [DEVICE_MAC], dest='8.8.8.8')

    def test_no_dest_raises_value_error(self):
        controller = _controller()

        with pytest.raises(ValueError):
            controller.ping(SITE_ID, [DEVICE_MAC])


class TestTraceroute:
    def test_sends_expected_body_without_packet_fields(self, requests_mock, monkeypatch):
        _install_fake_ws_client(monkeypatch, [
            _troubleshooting_message(DEVICE_MAC, 0, 'traceroute to 8.8.8.8\n', True),
        ])
        requests_mock.post(
            f'{BASE_URL}/{ORG_ID}/api/v2/sites/{SITE_ID}/tools/network-check/1',
            json=_ack_response(),
        )
        controller = _controller()

        result = controller.traceroute(SITE_ID, [DEVICE_MAC], dest='8.8.8.8')

        assert result == {DEVICE_MAC: 'traceroute to 8.8.8.8\n'}
        sent = requests_mock.request_history[-1].json()
        assert sent == {
            'deviceType': 0,
            'source': [DEVICE_MAC],
            'nid': _FIXED_NID,
            'destType': 0,
            'dest': '8.8.8.8',
        }


class TestDnsLookup:
    def test_sends_hostname_as_dest(self, requests_mock, monkeypatch):
        _install_fake_ws_client(monkeypatch, [
            _troubleshooting_message(DEVICE_MAC, 0, 'www.google.com has address 1.2.3.4\n', True),
        ])
        requests_mock.post(
            f'{BASE_URL}/{ORG_ID}/api/v2/sites/{SITE_ID}/tools/network-check/2',
            json=_ack_response(),
        )
        controller = _controller()

        result = controller.dns_lookup(SITE_ID, [DEVICE_MAC], hostname='www.google.com')

        assert result == {DEVICE_MAC: 'www.google.com has address 1.2.3.4\n'}
        sent = requests_mock.request_history[-1].json()
        assert sent['destType'] == 0
        assert sent['dest'] == 'www.google.com'
        assert 'packetSize' not in sent


class TestArpTable:
    def test_sends_no_destination_fields(self, requests_mock, monkeypatch):
        _install_fake_ws_client(monkeypatch, [
            _troubleshooting_message(DEVICE_MAC, 0, '? (10.0.0.1) at aa:bb on eth0\n', True),
        ])
        requests_mock.post(
            f'{BASE_URL}/{ORG_ID}/api/v2/sites/{SITE_ID}/tools/network-check/3',
            json=_ack_response(),
        )
        controller = _controller()

        result = controller.arp_table(SITE_ID, [DEVICE_MAC])

        assert result == {DEVICE_MAC: '? (10.0.0.1) at aa:bb on eth0\n'}
        sent = requests_mock.request_history[-1].json()
        assert sent == {'deviceType': 0, 'source': [DEVICE_MAC], 'nid': _FIXED_NID}
