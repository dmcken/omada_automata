'''Shared response-envelope handling.

Every TP-Link Omada Cloud API observed so far - the global unified-ID
service, Cloud Manager (account/organization), and the per-organization
Essential Controller (both its internal api/v2 routes and its
openapi/v1|v2 routes) - wraps every response the same way:
{"errorCode": int, "message"|"msg": str, "result": ...}, and answers
with HTTP 200 even when errorCode is non-zero. HTTP-level non-200 has
only been seen for transport-level failures (proxy/gateway errors),
never as this API family's own way of reporting a rejected request.
'''
from __future__ import annotations

import requests

from . import exceptions


def unwrap(response: requests.Response, endpoint: str):
    '''Validate HTTP status + envelope errorCode, return `result`.

    Args:
        response: The raw response.
        endpoint: Short label for error messages (path is enough - the
            caller already knows the host).

    Raises:
        exceptions.ApiError: HTTP-level failure, non-JSON body, or a
            non-zero errorCode in the envelope.

    Returns:
        The decoded `result` value (dict, list, or None).
    '''
    if response.status_code != 200:
        raise exceptions.ApiError(response.status_code, response.text[:200], endpoint)

    try:
        data = response.json()
    except ValueError as exc:
        raise exceptions.ApiError(-1, "Non-JSON response", endpoint) from exc

    error_code = data.get('errorCode', -1)
    if error_code != 0:
        message = data.get('message') or data.get('msg') or ''
        raise exceptions.ApiError(error_code, message, endpoint)

    return data.get('result')
