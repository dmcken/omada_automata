#!/usr/bin/env python3
'''List every organization on this account, one at a time, with the
sites, devices, and clients that fall under each.

Reads credentials from examples/.env (see examples/.env.example) and
reuses a cached session the same way walkthrough.py does (see there
for the session-caching pattern), so repeated runs don't repeat the
full login chain.

Usage:
    cp examples/.env.example examples/.env   # then fill in your values
    uv sync --group examples
    uv run python examples/list_orgs_and_sites.py

Devices/clients are printed from EssentialController.get_devices()/
get_clients()'s raw result - confirmed live, but not yet parsed into a
dataclass (see essential.py's module docstring) - only a handful of
fields are pulled out here, defensively (.get() with fallbacks), since
the exact key set may not hold for every device/client type.
'''
from __future__ import annotations

import logging
import pathlib

import _session_cache
import dotenv

from omada_automata import exceptions

logging.basicConfig(level=logging.WARNING, format='%(levelname)s %(name)s: %(message)s')


def _print_devices(controller, site_id: str) -> None:
    try:
        result = controller.get_devices(site_id, page=1, page_size=100)
    except exceptions.ApiError as exc:
        print(f"    ERROR fetching devices: {exc}")
        return

    devices = result.get('data', [])
    if not devices:
        print("    (no devices)")
        return
    for device in devices:
        name = device.get('name', '?')
        dev_type = device.get('type', '?')
        model = device.get('model', '?')
        ip = device.get('ip', '?')
        status = device.get('status', '?')
        print(f"    - {name} [{dev_type}/{model}] ip={ip} status={status}")


def _print_clients(controller, site_id: str) -> None:
    try:
        result = controller.get_clients(site_id, active_only=True, page=1, page_size=100)
    except exceptions.ApiError as exc:
        print(f"    ERROR fetching clients: {exc}")
        return

    clients = result.get('data', [])
    if not clients:
        print("    (no clients)")
        return
    for client in clients:
        name = client.get('name', '?')
        mac = client.get('mac', '?')
        ip = client.get('ip', '?')
        via = client.get('connectDevType', '?')
        link = 'wireless' if client.get('wireless') else 'wired'
        print(f"    - {name} ({mac}) ip={ip} {link} via {via}")


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

            print("    Devices:")
            _print_devices(controller, site.site_id)

            print("    Clients:")
            _print_clients(controller, site.site_id)


if __name__ == '__main__':
    main()
