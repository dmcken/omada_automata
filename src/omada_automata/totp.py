'''TOTP code generation, for completing OmadaCloudAccount.verify_mfa()
without a human relaying a code each time.

Requires the `totp` extra (pyotp) - kept optional since most of this
package's callers won't have a 2FA-enabled account to automate against
(see exceptions.MfaRequired and account.py's module docstring for the
verify_mfa() flow this feeds).

The secret is the base32 value from the account's authenticator app
setup - normally only ever shown as a QR code (an otpauth:// URI), not
as text, so it has to be decoded out of that QR code once (e.g. via
`zbarimg`/any QR reader) to use it here. Confirmed live end-to-end
against a real "App Authentication" (Authy) TOTP account, using the
exact secret/algorithm/digit-count/period its own QR code encoded
(SHA1, 6 digits, 30s period - pyotp's own defaults, but the QR code's
otpauth:// URI is the authoritative source if a real account ever
differs).
'''
from __future__ import annotations

import time

import pyotp


def generate_totp_code(secret: str, at_time: float | None = None) -> str:
    '''Current 6-digit TOTP code for `secret`.

    Args:
        secret: The base32 TOTP secret (decoded from the account's
            authenticator-app QR code).
        at_time: Unix timestamp to generate the code for - defaults to
            now. Exposed mainly so generate_totp_codes_with_drift_tolerance()
            can generate adjacent time-step codes.
    '''
    return pyotp.TOTP(secret).at(at_time if at_time is not None else time.time())


def generate_totp_codes_with_drift_tolerance(
    secret: str, steps: int = 1, period: int = 30
) -> list[str]:
    '''The current TOTP code plus `steps` adjacent codes on either side
    (oldest first), for a caller that wants to try more than one code
    in case of clock drift between this machine and TP-Link's server -
    login()/verify_mfa() don't do this automatically, since a wrong
    code is otherwise indistinguishable from a genuinely wrong one.
    '''
    now = time.time()
    offsets = range(-steps, steps + 1)
    # De-duplicate while preserving order, in case `period` is small
    # enough that adjacent offsets land on the same time-step.
    seen: dict[str, None] = {}
    for offset in offsets:
        code = generate_totp_code(secret, now + offset * period)
        seen[code] = None
    return list(seen)
