'''Tests for OnPremiseController - an on-premise hardware controller
(e.g. an OC200) reached through Cloud Access.'''
import base64
import typing
import uuid

import pytest
import requests

from omada_automata import exceptions
from omada_automata.onpremise import OnPremiseController

BASE_URL = (
    'https://use1-api-omada-controller-connector.tplinkcloud.com'
    '/omadac/0000000000000000000000000000000000000000'
)
OMADAC_ID = 'fake-omadac-id-0000000000000000'
SITE_ID = 'aaaaaaaaaaaaaaaaaaaaaaaa'
DEVICE_MAC = 'AA-BB-CC-DD-EE-FF'
_FIXED_UUID = uuid.UUID('11111111-1111-1111-1111-111111111111')
_FIXED_NID = _FIXED_UUID.hex


def _b64(text: str) -> str:
    return base64.b64encode(text.encode()).decode()


def _controller():
    return OnPremiseController(
        session=requests.Session(),
        device_id='0000000000000000000000000000000000000000',
        omadac_id=OMADAC_ID,
        connector_base=BASE_URL,
        csrf_token='fake-csrf-token',
        frontend_origin='https://use1-omada-cloud.tplinkcloud.com',
    )


class TestHeaders:
    def test_includes_csrf_token(self):
        controller = _controller()
        assert controller._headers()['Csrf-Token'] == 'fake-csrf-token'

    def test_no_csrf_token_omits_header(self):
        controller = OnPremiseController(
            session=requests.Session(),
            device_id='dev',
            omadac_id=OMADAC_ID,
            connector_base=BASE_URL,
            csrf_token=None,
        )
        assert 'Csrf-Token' not in controller._headers()

    def test_no_shiro_priming_call(self, requests_mock):
        '''Unlike EssentialController, no current/login-status call
        should happen before a normal data call - confirmed live that
        on-premise data calls just work immediately.'''
        requests_mock.get(
            f'{BASE_URL}/{OMADAC_ID}/api/v2/organization/site-ids',
            json={'errorCode': 0, 'msg': 'Success.', 'result': {'siteIds': [SITE_ID]}},
        )
        controller = _controller()

        controller.get_site_ids()

        assert len(requests_mock.request_history) == 1
        assert 'login-status' not in requests_mock.request_history[0].url


class TestGetSites:
    def test_parses_site_fields(self, requests_mock):
        requests_mock.get(
            f'{BASE_URL}/{OMADAC_ID}/api/v2/user/sites',
            json={
                'errorCode': 0, 'msg': 'Success.',
                'result': {
                    'totalRows': 1, 'currentPage': 1, 'currentSize': 100,
                    'data': [{'id': SITE_ID, 'name': 'Head Office', 'type': 0, 'favorite': False}],
                },
            },
        )
        controller = _controller()

        sites = controller.get_sites()

        assert len(sites) == 1
        assert sites[0].site_id == SITE_ID
        assert sites[0].name == 'Head Office'


class TestGetSiteIds:
    def test_returns_id_list(self, requests_mock):
        requests_mock.get(
            f'{BASE_URL}/{OMADAC_ID}/api/v2/organization/site-ids',
            json={'errorCode': 0, 'msg': 'Success.', 'result': {'siteIds': [SITE_ID]}},
        )
        controller = _controller()

        assert controller.get_site_ids() == [SITE_ID]


class TestGetAlertCount:
    def test_not_site_scoped(self, requests_mock):
        requests_mock.get(
            f'{BASE_URL}/{OMADAC_ID}/api/v2/alerts/num',
            json={'errorCode': 0, 'msg': 'Success.', 'result': {'alertNum': 1}},
        )
        controller = _controller()

        assert controller.get_alert_count() == 1


class TestGetDevices:
    def test_uses_adopted_grid_with_no_site_id(self, requests_mock):
        requests_mock.get(
            f'{BASE_URL}/{OMADAC_ID}/api/v2/grid/devices/adopted',
            json={'errorCode': 0, 'msg': 'Success.', 'result': {'data': []}},
        )
        controller = _controller()

        controller.get_devices(page=2, page_size=25)

        query = requests_mock.request_history[0].qs
        assert query['currentpage'] == ['2']
        assert query['currentpagesize'] == ['25']
        assert query['asynccolumns'] == ['client']

    def test_non_zero_error_code_raises(self, requests_mock):
        requests_mock.get(
            f'{BASE_URL}/{OMADAC_ID}/api/v2/grid/devices/adopted',
            json={'errorCode': -1, 'msg': 'boom', 'result': None},
        )
        controller = _controller()

        with pytest.raises(exceptions.ApiError):
            controller.get_devices()


class TestGetClients:
    def test_same_shape_as_essential(self, requests_mock):
        requests_mock.post(
            f'{BASE_URL}/openapi/v2/{OMADAC_ID}/sites/{SITE_ID}/clients',
            json={'errorCode': 0, 'msg': 'Success.', 'result': {'data': []}},
        )
        controller = _controller()

        controller.get_clients(SITE_ID, active_only=True, page=1, page_size=10)

        sent = requests_mock.request_history[0].json()
        assert sent == {
            'filters': {'active': True}, 'sorts': {}, 'page': 1, 'pageSize': 10, 'scope': 1,
        }


class _FakeSockJsStompClient:
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
    monkeypatch.setattr('omada_automata._network_check.uuid.uuid4', lambda: _FIXED_UUID)
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
    def test_sends_expected_body_and_uses_site_scoped_subscription(
        self, requests_mock, monkeypatch
    ):
        '''Confirmed live: the POST path has no site_id (unlike
        Essential), but the WebSocket subscribe destination still
        does.'''
        fake_class = _install_fake_ws_client(monkeypatch, [
            _troubleshooting_message(DEVICE_MAC, 0, 'PING 8.8.8.8 ...\n', True),
        ])
        requests_mock.post(
            f'{BASE_URL}/{OMADAC_ID}/api/v2/tools/network-check/0',
            json=_ack_response(),
        )
        controller = _controller()

        result = controller.ping(SITE_ID, [DEVICE_MAC], dest='8.8.8.8')

        assert result == {DEVICE_MAC: 'PING 8.8.8.8 ...\n'}
        sent_url = requests_mock.request_history[-1].url
        assert f'/{OMADAC_ID}/api/v2/tools/network-check/0' in sent_url
        assert f'sites/{SITE_ID}' not in sent_url
        assert fake_class.last_instance.subscribed == [
            f'/user/queue/ws/{OMADAC_ID}/sites/{SITE_ID}/status'
        ]
        assert fake_class.last_instance.closed is True

    def test_gateway_interface_fields(self, requests_mock, monkeypatch):
        '''Confirmed live: a Gateway source (device_type=2) doing Ping
        includes interfaceId/interfaceType.'''
        _install_fake_ws_client(monkeypatch, [
            _troubleshooting_message(DEVICE_MAC, 0, 'ok\n', True),
        ])
        requests_mock.post(
            f'{BASE_URL}/{OMADAC_ID}/api/v2/tools/network-check/0',
            json=_ack_response(),
        )
        controller = _controller()

        controller.ping(
            SITE_ID, [DEVICE_MAC], dest='8.8.8.8', device_type=2,
            interface_id='69ae22ed429b151e2c404a11', interface_type=1,
        )

        sent = requests_mock.request_history[-1].json()
        assert sent['deviceType'] == 2
        assert sent['interfaceId'] == '69ae22ed429b151e2c404a11'
        assert sent['interfaceType'] == 1

    def test_device_error_raises_api_error(self, requests_mock, monkeypatch):
        _install_fake_ws_client(monkeypatch, [])
        requests_mock.post(
            f'{BASE_URL}/{OMADAC_ID}/api/v2/tools/network-check/0',
            json=_ack_response(error_code=-1),
        )
        controller = _controller()

        with pytest.raises(exceptions.ApiError):
            controller.ping(SITE_ID, [DEVICE_MAC], dest='8.8.8.8')


class TestTraceroute:
    def test_sends_expected_body_without_packet_fields(self, requests_mock, monkeypatch):
        _install_fake_ws_client(monkeypatch, [
            _troubleshooting_message(DEVICE_MAC, 0, 'traceroute to 8.8.8.8\n', True),
        ])
        requests_mock.post(
            f'{BASE_URL}/{OMADAC_ID}/api/v2/tools/network-check/1',
            json=_ack_response(),
        )
        controller = _controller()

        result = controller.traceroute(SITE_ID, [DEVICE_MAC], dest='8.8.8.8')

        assert result == {DEVICE_MAC: 'traceroute to 8.8.8.8\n'}
        sent = requests_mock.request_history[-1].json()
        assert sent == {
            'deviceType': 0, 'source': [DEVICE_MAC], 'nid': _FIXED_NID,
            'destType': 0, 'dest': '8.8.8.8',
        }


class TestDnsLookup:
    def test_sends_hostname_as_dest(self, requests_mock, monkeypatch):
        _install_fake_ws_client(monkeypatch, [
            _troubleshooting_message(DEVICE_MAC, 0, 'www.google.com has address 1.2.3.4\n', True),
        ])
        requests_mock.post(
            f'{BASE_URL}/{OMADAC_ID}/api/v2/tools/network-check/2',
            json=_ack_response(),
        )
        controller = _controller()

        result = controller.dns_lookup(SITE_ID, [DEVICE_MAC], hostname='www.google.com')

        assert result == {DEVICE_MAC: 'www.google.com has address 1.2.3.4\n'}
        sent = requests_mock.request_history[-1].json()
        assert sent['destType'] == 0
        assert sent['dest'] == 'www.google.com'


class TestArpTable:
    def test_confirmed_finish_true_on_premise(self, requests_mock, monkeypatch):
        '''Unlike Essential Controller, ARP Table was confirmed live to
        correctly set finish:true on-premise - this test locks in that
        the happy path (no idle-timeout fallback needed) still works.'''
        _install_fake_ws_client(monkeypatch, [
            _troubleshooting_message(DEVICE_MAC, 0, '? (10.0.0.1) at aa:bb on eth0\n', True),
        ])
        requests_mock.post(
            f'{BASE_URL}/{OMADAC_ID}/api/v2/tools/network-check/3',
            json=_ack_response(),
        )
        controller = _controller()

        result = controller.arp_table(SITE_ID, [DEVICE_MAC])

        assert result == {DEVICE_MAC: '? (10.0.0.1) at aa:bb on eth0\n'}
        sent = requests_mock.request_history[-1].json()
        assert sent == {'deviceType': 0, 'source': [DEVICE_MAC], 'nid': _FIXED_NID}
