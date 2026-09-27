'''Tests for the SockJS/STOMP framing helpers - the pure parsing/
encoding functions only. SockJsStompClient itself opens a real
WebSocket in its constructor, so it's exercised indirectly via
test_essential.py's network-check tests instead (with the class
monkeypatched out) rather than unit-tested directly here.'''
import json

from omada_automata._sockjs_stomp import (
    _encode_stomp_frame,
    _parse_sockjs_frame,
    _parse_stomp_frame,
    _random_sockjs_path_segment,
)


class TestRandomSockjsPathSegment:
    def test_shape_is_number_slash_alnum(self):
        segment = _random_sockjs_path_segment()
        server_id, session_id = segment.split('/')
        assert server_id.isdigit()
        assert 0 <= int(server_id) <= 999
        assert len(session_id) == 8
        assert session_id.isalnum()

    def test_calls_are_not_all_identical(self):
        # Not a strict guarantee, but collisions across a handful of
        # calls would indicate the randomness isn't doing anything.
        segments = {_random_sockjs_path_segment() for _ in range(10)}
        assert len(segments) > 1


class TestEncodeStompFrame:
    def test_produces_null_terminated_frame_with_headers(self):
        frame = _encode_stomp_frame('CONNECT', {'accept-version': '1.1,1.0'}, '')
        assert frame == 'CONNECT\naccept-version:1.1,1.0\n\n\x00'

    def test_no_headers(self):
        frame = _encode_stomp_frame('DISCONNECT', {})
        assert frame == 'DISCONNECT\n\n\x00'


class TestParseSockjsFrame:
    def test_open_frame(self):
        assert _parse_sockjs_frame('o') == ('o', None)

    def test_heartbeat_frame(self):
        assert _parse_sockjs_frame('h') == ('h', None)

    def test_array_frame_decodes_json(self):
        raw = 'a' + json.dumps(['CONNECTED\nversion:1.1\n\n\x00'])
        kind, payload = _parse_sockjs_frame(raw)
        assert kind == 'a'
        assert payload == ['CONNECTED\nversion:1.1\n\n\x00']

    def test_close_frame_decodes_code_and_reason(self):
        kind, payload = _parse_sockjs_frame('c[3000,"Go away!"]')
        assert kind == 'c'
        assert payload == [3000, 'Go away!']

    def test_empty_string(self):
        assert _parse_sockjs_frame('') == (None, None)


class TestParseStompFrame:
    def test_splits_command_headers_and_body(self):
        raw = (
            'MESSAGE\ndestination:/topic/x\ncontent-length:13\n\n'
            '{"ok": true}\x00'
        )
        command, headers, body = _parse_stomp_frame(raw)
        assert command == 'MESSAGE'
        assert headers == {'destination': '/topic/x', 'content-length': '13'}
        assert body == '{"ok": true}'

    def test_no_headers(self):
        command, headers, body = _parse_stomp_frame('CONNECTED\n\n\x00')
        assert command == 'CONNECTED'
        assert headers == {}
        assert body == ''

    def test_tolerates_trailing_newline_after_null(self):
        command, _headers, body = _parse_stomp_frame('CONNECTED\n\n\x00\n')
        assert command == 'CONNECTED'
        assert body == ''
