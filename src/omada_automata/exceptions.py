'''General exceptions'''
from __future__ import annotations


class OmadaAutomataError(Exception):
    '''Base exception for this package.'''


class AccountUnavailable(OmadaAutomataError):
    '''Raised when the TP-Link cloud identity service can't be reached
    (connection/timeout), or the SSO hand-off (login -> oauth/authorize
    -> login-with-uid-code) breaks in a way that isn't a plain
    rejected-credentials failure.
    '''


class LoginFailed(OmadaAutomataError):
    '''Raised when email/password authentication is rejected.'''


class ApiError(OmadaAutomataError):
    '''Raised when a call fails at the HTTP level, or succeeds at the
    HTTP level but the JSON envelope reports errorCode != 0 - every
    TP-Link Omada Cloud API observed (unified ID, Cloud Manager,
    Essential Controller) answers with HTTP 200 even on failure, so
    errorCode is the real success/failure signal.
    '''

    def __init__(self, error_code: int, message: str, endpoint: str | None = None) -> None:
        self.error_code = error_code
        self.message = message
        self.endpoint = endpoint
        prefix = f"{endpoint}: " if endpoint else ""
        super().__init__(f"{prefix}[{error_code}] {message}")
