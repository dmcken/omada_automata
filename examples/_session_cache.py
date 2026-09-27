'''Shared login/session-cache helpers for the scripts under examples/ -
not part of the omada_automata package itself, just avoids repeating
this boilerplate in every example script.

See walkthrough.py's module docstring for the caching pattern this
supports: a successful login() is cached to SESSION_CACHE_PATH
(gitignored - it holds a live session cookie, treat it like a
password) and reused on the next run via restore_session_state(),
skipping the full SSO login chain entirely as long as is_logged_in()
still says it's valid.

If the account has 2FA enabled, login_with_cache() completes it two
ways: automatically via OMADA_TOTP_SECRET in examples/.env if set (the
base32 secret decoded from the account's authenticator-app QR code -
confirmed live end-to-end against a real Authy/TOTP account), or by
prompting on stdin for a code otherwise. Either way this is still only
practical for an interactive-ish caller (or one willing to keep a TOTP
secret alongside its other credentials) - a fully unattended/cron
caller without OMADA_TOTP_SECRET configured would need to mostly rely
on a long-lived cached session instead and only handle this on the
rare occasions it's actually needed.
'''
from __future__ import annotations

import json
import os
import pathlib
import stat
import sys

import omada_automata

try:
    from omada_automata import totp as _totp
except ImportError:
    _totp = None

SESSION_CACHE_PATH = pathlib.Path(__file__).parent / '.omada_session.json'


def require_env(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        sys.exit(
            f"Missing required {name} - copy examples/.env.example to "
            "examples/.env and fill it in"
        )
    return value


def load_cached_account() -> omada_automata.OmadaCloudAccount | None:
    '''Restore a session cached by a previous run, if one exists and
    is still valid - is_logged_in() makes one real request, so this
    still costs a round trip, just a much cheaper one than the full
    3-step login chain.
    '''
    if not SESSION_CACHE_PATH.exists():
        return None
    account = omada_automata.OmadaCloudAccount()
    account.restore_session_state(json.loads(SESSION_CACHE_PATH.read_text()))
    if not account.is_logged_in():
        print(f"Cached session in {SESSION_CACHE_PATH} has expired")
        return None
    print(f"Reusing cached session from {SESSION_CACHE_PATH}")
    return account


def save_session_cache(account: omada_automata.OmadaCloudAccount) -> None:
    SESSION_CACHE_PATH.write_text(json.dumps(account.get_session_state()))
    SESSION_CACHE_PATH.chmod(stat.S_IRUSR | stat.S_IWUSR)  # 0600 - as sensitive as a password


def logout_and_exit() -> None:
    account = load_cached_account()
    if account is None:
        sys.exit("No cached (still-valid) session to log out of")
    account.logout()
    SESSION_CACHE_PATH.unlink(missing_ok=True)
    print("Logged out, session cache removed")


def _complete_mfa_automatically(
    account: omada_automata.OmadaCloudAccount, totp_secret: str
) -> bool:
    '''Try each of a few adjacent-time-step TOTP codes (drift
    tolerance) against the pending challenge login() just raised.
    Returns False (never raises for a rejected code) if every
    candidate was rejected, so the caller can fall back to prompting -
    verify_mfa()'s pending state survives a rejected code, so trying
    more than one here is safe.
    '''
    for code in _totp.generate_totp_codes_with_drift_tolerance(totp_secret):
        try:
            account.verify_mfa(code)
            return True
        except omada_automata.exceptions.LoginFailed:
            continue
    return False


def _complete_mfa_interactively(
    account: omada_automata.OmadaCloudAccount,
    exc: omada_automata.exceptions.MfaRequired,
    max_attempts: int = 3,
) -> None:
    print(f"Two-factor authentication required (type {exc.mfa_type}).")
    for attempt in range(1, max_attempts + 1):
        code = input("Enter the 6-digit code from your authenticator app: ").strip()
        try:
            account.verify_mfa(code)
            return
        except omada_automata.exceptions.LoginFailed as verify_exc:
            print(f"  Rejected: {verify_exc}")
            if attempt == max_attempts:
                sys.exit("Too many failed MFA attempts, giving up.")


def _complete_mfa(
    account: omada_automata.OmadaCloudAccount, exc: omada_automata.exceptions.MfaRequired
) -> None:
    totp_secret = os.environ.get('OMADA_TOTP_SECRET')
    if totp_secret and _totp is not None:
        if _complete_mfa_automatically(account, totp_secret):
            print("Completed 2FA automatically via OMADA_TOTP_SECRET.")
            return
        print("Auto-generated TOTP codes were all rejected - falling back to a manual code.")

    _complete_mfa_interactively(account, exc)


def login_with_cache(email: str, password: str) -> omada_automata.OmadaCloudAccount:
    '''Reuse a cached session if one is still valid, otherwise run the
    full login chain - completing 2FA per _complete_mfa() above if the
    account has it enabled - and cache the result for next time.
    '''
    account = load_cached_account()
    if account is not None:
        return account

    account = omada_automata.OmadaCloudAccount()
    try:
        account.login(email, password)
    except omada_automata.exceptions.MfaRequired as exc:
        _complete_mfa(account, exc)
    except omada_automata.exceptions.LoginFailed as exc:
        sys.exit(f"Login rejected: {exc}")
    except omada_automata.exceptions.AccountUnavailable as exc:
        sys.exit(f"Could not reach TP-Link Omada Cloud: {exc}")
    save_session_cache(account)
    return account
