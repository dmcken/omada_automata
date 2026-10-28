'''Shared network-check (ping/traceroute/dns_lookup/arp_table)
protocol - a REST POST to queue a test, then its actual output
streamed back over a WebSocket (see _sockjs_stomp.py for that
transport). Confirmed live to be byte-for-byte identical between
Essential Controller and an on-premise controller accessed through
Cloud Access (same underlying controller software) - see essential.py
and onpremise.py's module docstrings for which side confirmed which
detail, and for how each builds the `post_path`/`ws_url`/
`subscribe_destination` this module is handed.

    POST {post_path}
    {"deviceType", "source": [macs], "nid": <random correlation token>,
     ...test-specific fields...}
    -> {"result": {"deviceResult": [{"errorCode", "mac", "nid"}, ...]}}

`test` is 0=Ping, 1=Traceroute, 2=DNS Lookup, 3=ARP Table (confirmed
from the frontend's own enum, and each test number's exact body
confirmed live on both Essential and on-premise). Ping/Traceroute/DNS
Lookup also take `destType` (0=hostname-or-IP, in which case `dest`
holds it; 1=a known client, in which case `client` holds its MAC) -
ARP Table takes no destination at all. Ping alone also takes
`packetSize`/`count`. A Gateway source (deviceType 2) doing Ping or
Traceroute also takes `interfaceId`/`interfaceType` (confirmed live,
on-premise only, to pick which WAN to test from) - NOT confirmed on
Essential Controller specifically, but the identical backend makes it
very likely to apply there too.

`source` here is always a list, even for one device - confirmed live
on both sides for this general multi-device-capable flow. A single
bare MAC string (not a list) was also observed live, on-premise only,
for a narrower case (the controller testing from itself, deviceType 3)
- not supported here, since every controller class's public
ping()/traceroute()/etc. methods are built around the list form.

The server pushes one or more STOMP MESSAGE frames to
`subscribe_destination`, each shaped
{"type":"troubleshootingTest","data":{"nid","mac","seq","finish","msg"}}
- `msg` is base64-encoded raw device CLI output text (literally the
device's own command's stdout - `ping`, `traceroute`, `nslookup`,
`arp`), `seq` numbers the chunks. Confirmed live on Essential Controller
that the last chunk has `finish:true` for Ping/Traceroute/DNS Lookup,
but NOT for ARP Table - its one output chunk never got `finish:true`
even 45s later. Confirmed live on an on-premise controller that ARP
Table *does* get `finish:true` there - a genuine behavioral difference
between the two (different backend versions, presumably), not a
mistake in either observation. run() always applies the idle-timeout
fallback below regardless of which side it's talking to, since trusting
`finish` alone would break on Essential and the fallback is harmless
(never triggers) wherever `finish` already arrives correctly.
'''
from __future__ import annotations

import base64
import uuid

from . import exceptions

TEST_PING = 0
TEST_TRACEROUTE = 1
TEST_DNS_LOOKUP = 2
TEST_ARP_TABLE = 3

DEFAULT_TIMEOUT = 70.0
# See the module docstring - comfortably above the ~9s gaps observed
# live between Ping's own chunks, so it won't cut those short, while
# still ending an ARP-Table-without-finish wait long before the overall
# timeout above.
IDLE_TIMEOUT = 20.0


def dest_body(dest: str | None, dest_client_mac: str | None) -> dict:
    '''Build the destType/dest-or-client portion of a Ping/Traceroute/
    DNS Lookup body.'''
    if dest_client_mac:
        return {'destType': 1, 'client': dest_client_mac}
    if dest is None:
        raise ValueError("Either dest or dest_client_mac must be given")
    return {'destType': 0, 'dest': dest}


def run(
    post_fn,
    post_path: str,
    ws_url: str,
    origin: str,
    cookie_header: str,
    csrf_token: str | None,
    subscribe_destination: str,
    device_type: int,
    source_macs: list[str],
    extra_body: dict,
    timeout: float = DEFAULT_TIMEOUT,
    idle_timeout: float = IDLE_TIMEOUT,
) -> dict[str, str]:
    '''Run one network-check test and collect its output per source
    device. Blocks until every queued device's output finishes (or
    looks finished, per the idle-timeout fallback - see module
    docstring) or `timeout` elapses.

    Requires the `network-check` extra (websocket-client).

    Args:
        post_fn: A bound `_post(path, json_body)` method on the caller,
            already scoped to the right controller (and, for Essential,
            site) base path.
        post_path: Full path to POST the test request to.
        ws_url: Full WebSocket base URL (wss://.../ws/status) to open.
        origin: Origin header for the WebSocket handshake.
        cookie_header: Cookie header for the WebSocket handshake.
        csrf_token: Sent as the STOMP CONNECT frame's Csrf-Token.
        subscribe_destination: STOMP destination to subscribe to for
            this test's results.
        device_type, source_macs, extra_body: Merged into the POST
            body as {"deviceType", "source": source_macs, "nid": ...,
            **extra_body}.

    Returns:
        dict[str, str]: source MAC -> its decoded, concatenated output
            text.

    Raises:
        exceptions.ApiError: The test was rejected outright, or a
            queued device reported its own error.
        TimeoutError: Not every device's output finished in time.
        _sockjs_stomp.StompError: The WebSocket/STOMP handshake or
            connection itself failed.
    '''
    from . import _sockjs_stomp  # local import: only this needs the 'network-check' extra

    nid = uuid.uuid4().hex
    body = {'deviceType': device_type, 'source': list(source_macs), 'nid': nid, **extra_body}

    client = _sockjs_stomp.SockJsStompClient(
        ws_url, origin, cookie_header, csrf_token or '', timeout=timeout
    )
    try:
        client.subscribe(subscribe_destination)

        result = post_fn(post_path, json_body=body)
        pending_macs = set()
        for device_result in result.get('deviceResult', []):
            if device_result.get('errorCode') != 0:
                raise exceptions.ApiError(
                    device_result.get('errorCode', -1),
                    f"Device {device_result.get('mac')} rejected the test",
                    post_path,
                )
            pending_macs.add(device_result['mac'])

        chunks: dict[str, list[tuple[int, str]]] = {}
        for message in client.iter_messages(idle_timeout=idle_timeout):
            if message.get('type') != 'troubleshootingTest':
                continue
            data = message.get('data', {})
            if data.get('nid') != nid:
                continue
            mac = data.get('mac')
            chunks.setdefault(mac, []).append((data.get('seq', 0), data.get('msg', '')))
            if data.get('finish'):
                pending_macs.discard(mac)
            if not pending_macs:
                break

        return {mac: _decode_chunks(parts) for mac, parts in chunks.items()}
    finally:
        client.close()


def _decode_chunks(parts: list[tuple[int, str]]) -> str:
    parts.sort(key=lambda p: p[0])
    return ''.join(base64.b64decode(msg).decode('utf-8', errors='replace') for _, msg in parts)
