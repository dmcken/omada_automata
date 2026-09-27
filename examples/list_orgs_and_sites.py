#!/usr/bin/env python3
'''List every organization on this account, one at a time, with the
sites that fall under each.

Reads credentials from examples/.env (see examples/.env.example) and
reuses a cached session the same way walkthrough.py does (see there
for the session-caching pattern), so repeated runs don't repeat the
full login chain.

Usage:
    cp examples/.env.example examples/.env   # then fill in your values
    uv sync --group examples
    uv run python examples/list_orgs_and_sites.py
'''
from __future__ import annotations

import logging
import pathlib

import _session_cache
import dotenv

from omada_automata import exceptions

logging.basicConfig(level=logging.WARNING, format='%(levelname)s %(name)s: %(message)s')


def main() -> None:
    dotenv.load_dotenv(pathlib.Path(__file__).parent / '.env')

    email = _session_cache.require_env('OMADA_EMAIL')
    password = _session_cache.require_env('OMADA_PASSWORD')

    account = _session_cache.login_with_cache(email, password)

    orgs = account.list_organizations()
    if not orgs:
        print("This account has no organizations.")
        return

    for org in orgs:
        print(f"\n{org.name} ({org.org_id})")
        print(f"  category={org.category}  role={org.role}  msp_mode={org.msp_mode}")

        try:
            controller = account.essential_controller(org.org_id)
        except exceptions.ApiError as exc:
            print(f"  no Essential Controller for this organization: {exc}")
            continue

        sites = controller.get_sites()
        if not sites:
            print("  (no sites)")
            continue

        for site in sites:
            favorite = ' [favorite]' if site.favorite else ''
            print(f"  - {site.name} ({site.site_id}){favorite}")


if __name__ == '__main__':
    main()
