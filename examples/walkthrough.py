#!/usr/bin/env python3
'''End-to-end walkthrough of omada_automata against a real account.

Reads credentials from examples/.env (see examples/.env.example) and
exercises every fetch method the package currently exposes: login (or
a cached session, see below), Cloud Manager account/organization data,
then every EssentialController method for each site in the chosen
organization.

Usage:
    cp examples/.env.example examples/.env   # then fill in your values
    uv sync --group examples
    uv run python examples/walkthrough.py

Session caching: a successful login() is cached to
examples/.omada_session.json (gitignored - it holds a live session
cookie, treat it like a password) and reused on the next run via
restore_session_state(), skipping the full SSO login chain entirely as
long as is_logged_in() still says it's valid. This is the pattern a
monitoring system invoked repeatedly (e.g. by cron) would use. Run with
--logout to log out and remove the cache:

    uv run python examples/walkthrough.py --logout

get_devices()/get_clients()/get_dashboard_overview() return raw dicts
whose exact shape isn't confirmed yet (see essential.py's module
docstring) - this script just pretty-prints whatever comes back so a
real run can be used to fill in proper dataclasses for them later.
'''
from __future__ import annotations

import argparse
import json
import logging
import os
import pathlib
import pprint
import stat
import sys
from collections.abc import Callable

import dotenv

import omada_automata
from omada_automata import exceptions

logging.basicConfig(level=logging.INFO, format='%(levelname)s %(name)s: %(message)s')

SESSION_CACHE_PATH = pathlib.Path(__file__).parent / '.omada_session.json'


def _require_env(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        sys.exit(
            f"Missing required {name} - copy examples/.env.example to "
            "examples/.env and fill it in"
        )
    return value


def _section(title: str) -> None:
    print(f"\n=== {title} ===")


def _safe_call(label: str, fn: Callable[[], object]) -> object | None:
    '''Run one of the "shape unconfirmed" raw-dict calls, printing
    whatever it returns (or the error) without aborting the rest of
    the walkthrough.
    '''
    print(f"\n{label}:")
    try:
        result = fn()
    except exceptions.ApiError as exc:
        print(f"  ERROR: {exc}")
        return None
    pprint.pprint(result)
    return result


def _load_cached_account() -> omada_automata.OmadaCloudAccount | None:
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


def _save_session_cache(account: omada_automata.OmadaCloudAccount) -> None:
    SESSION_CACHE_PATH.write_text(json.dumps(account.get_session_state()))
    SESSION_CACHE_PATH.chmod(stat.S_IRUSR | stat.S_IWUSR)  # 0600 - as sensitive as a password


def _logout_and_exit() -> None:
    account = _load_cached_account()
    if account is None:
        sys.exit("No cached (still-valid) session to log out of")
    account.logout()
    SESSION_CACHE_PATH.unlink(missing_ok=True)
    print("Logged out, session cache removed")


def main() -> None:
    dotenv.load_dotenv(pathlib.Path(__file__).parent / '.env')

    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        '--logout', action='store_true',
        help="Log out of the cached session and remove it, instead of running the walkthrough.",
    )
    args = parser.parse_args()

    if args.logout:
        _logout_and_exit()
        return

    email = _require_env('OMADA_EMAIL')
    password = _require_env('OMADA_PASSWORD')
    wanted_org_id = os.environ.get('OMADA_ORG_ID') or None
    wanted_site_id = os.environ.get('OMADA_SITE_ID') or None

    account = _load_cached_account()
    if account is None:
        account = omada_automata.OmadaCloudAccount()
        _section('Login')
        try:
            account.login(email, password)
        except exceptions.LoginFailed as exc:
            sys.exit(f"Login rejected: {exc}")
        except exceptions.AccountUnavailable as exc:
            sys.exit(f"Could not reach TP-Link Omada Cloud: {exc}")
        _save_session_cache(account)
    print(f"Logged in, account_id={account.account_id}")

    _section('Account detail')
    pprint.pprint(account.get_account_detail())

    _section('Organizations')
    orgs = account.list_organizations()
    for org in orgs:
        print(f"  {org.org_id}  {org.name!r}  sites={org.site_num}  category={org.category}")
    if not orgs:
        sys.exit("Account has no organizations - nothing further to exercise")

    org = orgs[0]
    if wanted_org_id:
        org = next((o for o in orgs if o.org_id == wanted_org_id), None)
        if org is None:
            sys.exit(f"OMADA_ORG_ID={wanted_org_id} not found in this account")
    print(f"Using organization: {org.name} ({org.org_id})")

    _section(f"Organization detail: {org.org_id}")
    pprint.pprint(account.get_organization(org.org_id))

    _section(f"Organization hosts: {org.org_id}")
    pprint.pprint(account.get_hosts(org.org_id))

    try:
        controller = account.essential_controller(org.org_id)
    except exceptions.ApiError as exc:
        sys.exit(f"Organization {org.org_id} has no Essential Controller: {exc}")

    _section('Current user')
    pprint.pprint(controller.get_current_user())

    _section('Sites')
    sites = controller.get_sites()
    for site in sites:
        print(f"  {site.site_id}  {site.name!r}  favorite={site.favorite}")
    print("Site IDs:", controller.get_site_ids())
    if not sites:
        sys.exit("Organization has no sites - nothing further to exercise")

    target_sites = sites
    if wanted_site_id:
        target_sites = [s for s in sites if s.site_id == wanted_site_id]
        if not target_sites:
            sys.exit(f"OMADA_SITE_ID={wanted_site_id} not found in this organization")

    for site in target_sites:
        _section(f"Site: {site.name} ({site.site_id})")

        print(f"Alert count: {controller.get_alert_count(site.site_id)}")

        _safe_call(
            "Devices (raw, shape unconfirmed)",
            lambda sid=site.site_id: controller.get_devices(sid, page=1, page_size=10),
        )
        _safe_call(
            "Clients (raw, shape unconfirmed)",
            lambda sid=site.site_id: controller.get_clients(
                sid, active_only=True, page=1, page_size=10
            ),
        )
        _safe_call(
            "Dashboard overview (raw, shape unconfirmed)",
            lambda sid=site.site_id: controller.get_dashboard_overview(sid),
        )


if __name__ == '__main__':
    main()
