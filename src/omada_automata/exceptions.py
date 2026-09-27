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


class MfaRequired(OmadaAutomataError):
    '''Raised by login() when the account has two-factor authentication
    enabled - email/password were accepted, but a code is also needed.
    Call verify_mfa(code) with a fresh code to complete login; the
    account/password don't need to be supplied again.

    Confirmed live: `mfa_type` 3 is TOTP (an authenticator app code) -
    no other type has been observed, so treat any other value as
    unconfirmed (email-based MFA looked to be type-agnostic, sharing
    the same account-level MFAEmail field regardless of which type is
    actually active - see account.py's module docstring).
    '''

    def __init__(self, mfa_type: int, supported_mfa_types: list[int], email: str | None) -> None:
        self.mfa_type = mfa_type
        self.supported_mfa_types = supported_mfa_types
        self.email = email
        super().__init__(
            f"MFA required (type {mfa_type}, supported types {supported_mfa_types})"
        )


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
