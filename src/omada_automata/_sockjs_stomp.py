'''Minimal synchronous SockJS+STOMP client - just enough to complete
one request/response round trip against the Essential Controller's
real-time status WebSocket (used for network-check results streaming;
see essential.py's module docstring for what that's for). This is
deliberately narrow, not a general STOMP client: connect, subscribe to
exactly the destinations the caller asks for, iterate messages, close.

Requires the `network-check` extra (websocket-client).

Reverse-engineered entirely from a captured HAR's WebSocket frames -
Chrome DevTools records SockJS/STOMP traffic as plain send/receive text
entries, which is how this was read out; no public documentation of
this protocol exists for TP-Link's controllers.

SockJS framing over the "websocket" transport specifically (the only
one this client implements - not SockJS's XHR-streaming/long-polling
fallback transports, which a real WebSocket connection never needs):
    o                          - open
    a["frame1","frame2",...]   - one or more STOMP frames, JSON-array-encoded
    h                          - heartbeat
    c[<code>,"<reason>"]       - close

STOMP frame: "COMMAND\nheader:value\n\n<body>\x00" - headers end at the
first blank line, body ends at the first NUL byte.

The WebSocket URL's two path segments before "/websocket"
(".../ws/status/{n}/{token}/websocket") are SockJS's own client-side
session routing (a random 0-999 "server id" and an 8-char alphanumeric
session id) - not anything the server hands out first. Confirmed by
every captured connection using different random values; generating
fresh ones here works the same way a real browser's SockJS client
does.
'''
from __future__ import annotations

import json
import logging
import random
import string
import time

import websocket

logger = logging.getLogger(__name__)

_HEARTBEAT_MS = 10000
_ALNUM = string.ascii_lowercase + string.digits


class StompError(Exception):
    '''Raised when the STOMP handshake fails, or the server sends an
    ERROR frame, or the SockJS connection closes unexpectedly.'''


class _IdleTimeout(Exception):
    '''Internal to iter_messages()'s `idle_timeout` - distinct from the
    connection's overall timeout (TimeoutError, still raised as such)
    so a caller can tell "nothing new arrived for a while" (expected,
    handled) apart from "the whole operation ran out of time"
    (unexpected, propagated). Never raised to callers directly.'''


def _random_sockjs_path_segment() -> str:
    server_id = str(random.randint(0, 999))
    session_id = ''.join(random.choices(_ALNUM, k=8))
    return f"{server_id}/{session_id}"


def _encode_stomp_frame(command: str, headers: dict, body: str = '') -> str:
    header_lines = ''.join(f"{k}:{v}\n" for k, v in headers.items())
    return f"{command}\n{header_lines}\n{body}\0"


def _parse_sockjs_frame(raw: str):
    '''Return (kind, payload) - payload is a list[str] of STOMP frames
    for kind "a" (or the close [code, reason] pair for kind "c"), None
    otherwise.
    '''
    if not raw:
        return None, None
    kind = raw[0]
    if kind in ('a', 'c'):
        return kind, json.loads(raw[1:])
    return kind, None


def _parse_stomp_frame(raw: str) -> tuple[str, dict, str]:
    '''Return (command, headers, body) for one STOMP frame.'''
    raw = raw.rstrip('\x00\n')
    head, _, body = raw.partition('\n\n')
    lines = head.split('\n')
    command = lines[0]
    headers = {}
    for line in lines[1:]:
        key, sep, value = line.partition(':')
        if sep:
            headers[key] = value
    return command, headers, body


class SockJsStompClient:
    '''One-shot SockJS+STOMP connection - connect, subscribe, iterate
    messages, close. Not reused across calls - a fresh connection per
    network-check call keeps connection lifecycle simple, at the cost
    of a little per-call handshake overhead.
    '''

    def __init__(
        self, ws_base_url: str, origin: str, cookie_header: str, csrf_token: str, timeout: float
    ) -> None:
        url = f"{ws_base_url}/{_random_sockjs_path_segment()}/websocket"
        self._ws = websocket.create_connection(
            url,
            header=[f"Origin: {origin}"],
            cookie=cookie_header,
            timeout=timeout,
        )
        self._deadline = time.time() + timeout
        try:
            self._connect(csrf_token)
        except Exception:
            self.close()
            raise

    def _recv_sockjs_frame(self, max_wait: float | None = None):
        '''Receive one SockJS frame. `max_wait`, if given and shorter
        than the time left until the connection's overall deadline,
        makes a timeout on this specific read raise _IdleTimeout
        instead of TimeoutError - see iter_messages().
        '''
        remaining = self._deadline - time.time()
        if remaining <= 0:
            raise TimeoutError("Timed out waiting for the WebSocket")
        wait = remaining if max_wait is None else min(remaining, max_wait)
        self._ws.settimeout(wait)
        try:
            raw = self._ws.recv()
        except websocket.WebSocketTimeoutException as exc:
            if max_wait is not None and wait < remaining:
                raise _IdleTimeout from exc
            raise TimeoutError("Timed out waiting for the WebSocket") from exc
        return _parse_sockjs_frame(raw)

    def _next_stomp_frame(self, max_wait: float | None = None) -> tuple[str, dict, str]:
        while True:
            kind, payload = self._recv_sockjs_frame(max_wait)
            if kind in ('h', 'o'):
                continue
            if kind == 'c':
                raise StompError(f"SockJS connection closed: {payload}")
            if kind == 'a':
                # Only ever observed one STOMP frame per SockJS "a"
                # frame live, but the format allows several - queueing
                # the rest would add real complexity for no observed
                # benefit, so only the first is used.
                return _parse_stomp_frame(payload[0])
            logger.debug("Ignoring unrecognized SockJS frame kind: %r", kind)

    def _send_stomp(self, command: str, headers: dict, body: str = '') -> None:
        frame = _encode_stomp_frame(command, headers, body)
        self._ws.send(json.dumps([frame]))

    def _connect(self, csrf_token: str) -> None:
        kind, _ = self._recv_sockjs_frame()
        if kind != 'o':
            raise StompError(f"Expected a SockJS open frame, got kind {kind!r}")

        self._send_stomp('CONNECT', {
            'Csrf-Token': csrf_token,
            'accept-version': '1.1,1.0',
            'heart-beat': f'{_HEARTBEAT_MS},{_HEARTBEAT_MS}',
        })
        command, _headers, body = self._next_stomp_frame()
        if command != 'CONNECTED':
            raise StompError(f"STOMP CONNECT rejected: {command} {body}")

    def subscribe(self, destination: str) -> str:
        '''Subscribe to one destination, returning its subscription id
        (not currently needed by callers - message frames are matched
        by content, not by which subscription delivered them - but
        returned for completeness/future use).
        '''
        sub_id = ''.join(random.choices(_ALNUM, k=12))
        self._send_stomp('SUBSCRIBE', {'id': sub_id, 'destination': destination})
        return sub_id

    def iter_messages(self, idle_timeout: float | None = None):
        '''Yield each STOMP MESSAGE frame's JSON-decoded body.

        Stops (a plain StopIteration, not an exception) if
        `idle_timeout` is given and that many seconds pass with no
        frame at all (not even a heartbeat) - see essential.py's
        module docstring for why this exists (some network-check test
        types never send an explicit "this is the last chunk" signal).
        Without `idle_timeout`, only stops by raising: TimeoutError if
        the connection's overall timeout elapses, or StompError if the
        server sends an ERROR frame. Frames this client doesn't care
        about (RECEIPT, etc.) are skipped silently either way.
        '''
        while True:
            try:
                command, headers, body = self._next_stomp_frame(idle_timeout)
            except _IdleTimeout:
                return
            if command == 'MESSAGE':
                try:
                    yield json.loads(body)
                except ValueError:
                    logger.debug("Ignoring non-JSON MESSAGE body: %r", body[:200])
            elif command == 'ERROR':
                raise StompError(f"STOMP ERROR: {headers} {body}")

    def close(self) -> None:
        try:
            self._send_stomp('DISCONNECT', {})
        except Exception:
            pass
        try:
            self._ws.close()
        except Exception:
            pass
