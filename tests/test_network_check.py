'''Tests for the pure helpers in _network_check.py - the shared
protocol EssentialController and OnPremiseController both delegate to
for ping()/traceroute()/dns_lookup()/arp_table(). run() itself is
exercised indirectly through each of those two classes' own tests
(with _sockjs_stomp.SockJsStompClient faked out), not duplicated here.'''
import base64

import pytest

from omada_automata._network_check import _decode_chunks, dest_body


class TestDestBody:
    def test_hostname_or_ip_uses_dest_type_0(self):
        assert dest_body('8.8.8.8', None) == {'destType': 0, 'dest': '8.8.8.8'}

    def test_client_mac_uses_dest_type_1(self):
        assert dest_body(None, '11-22-33-44-55-66') == {
            'destType': 1, 'client': '11-22-33-44-55-66',
        }

    def test_client_mac_takes_priority_over_dest(self):
        '''Matches the frontend's own precedence - if a caller somehow
        supplies both, the client-targeted form wins.'''
        result = dest_body('8.8.8.8', '11-22-33-44-55-66')
        assert result == {'destType': 1, 'client': '11-22-33-44-55-66'}

    def test_neither_raises(self):
        with pytest.raises(ValueError):
            dest_body(None, None)


class TestDecodeChunks:
    def test_joins_in_seq_order_regardless_of_input_order(self):
        parts = [
            (1, base64.b64encode(b'second ').decode()),
            (0, base64.b64encode(b'first ').decode()),
            (2, base64.b64encode(b'third').decode()),
        ]
        assert _decode_chunks(parts) == 'first second third'

    def test_single_chunk(self):
        parts = [(0, base64.b64encode(b'hello').decode())]
        assert _decode_chunks(parts) == 'hello'

    def test_empty(self):
        assert _decode_chunks([]) == ''
