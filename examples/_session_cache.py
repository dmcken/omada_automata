'''Shared login/session-cache helpers for the scripts under examples/ -
not part of the omada_automata package itself, just avoids repeating
this boilerplate in every example script.

See walkthrough.py's module docstring for the caching pattern this
supports: a successful login() is cached to SESSION_CACHE_PATH
(gitignored - it holds a live session cookie, treat it like a
password) and reused on the next run via restore_session_state(),
skipping the full SSO login chain entirely as long as is_logged_in()
still says it's valid.

If the account has 2FA enabled, login_with_cache() prompts on stdin for
a code (confirmed live against a TOTP/authenticator-app account - see
account.py's module docstring) - fine for these interactive example
scripts, but an unattended/cron caller would need a different
approach (e.g. mostly relying on a long-lived cached session and only
handling this prompt on the rare occasions it's actually needed).
'''
from __future__ import annotations

import json
import os
import pathlib
import stat
import sys

import omada_automata

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


def login_with_cache(email: str, password: str) -> omada_automata.OmadaCloudAccount:
    '''Reuse a cached session if one is still valid, otherwise run the
    full login chain - prompting on stdin for a 2FA code if the
    account has one configured - and cache the result for next time.
    '''
    account = load_cached_account()
    if account is not None:
        return account

    account = omada_automata.OmadaCloudAccount()
    try:
        account.login(email, password)
    except omada_automata.exceptions.MfaRequired as exc:
        _complete_mfa_interactively(account, exc)
    except omada_automata.exceptions.LoginFailed as exc:
        sys.exit(f"Login rejected: {exc}")
    except omada_automata.exceptions.AccountUnavailable as exc:
        sys.exit(f"Could not reach TP-Link Omada Cloud: {exc}")
    save_session_cache(account)
    return account
