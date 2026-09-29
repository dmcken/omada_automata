# Omada Automations
[![Tests](https://github.com/dmcken/omada_automata/actions/workflows/tests.yml/badge.svg)](https://github.com/dmcken/omada_automata/actions/workflows/tests.yml)
[![Ruff](https://github.com/dmcken/omada_automata/actions/workflows/ruff.yml/badge.svg)](https://github.com/dmcken/omada_automata/actions/workflows/ruff.yml)

Automate login to TP-Link's Omada Cloud (id.tplinkcloud.com /
omada-cloud web UI) and fetch data from an "Omada Essential" cloud-
hosted controller - sites, devices, clients, alerts.

## Modules

- `OmadaCloudAccount` - unified-ID SSO login (email/password), plus
  Cloud Manager account/organization data (organization list,
  per-organization API hosts). Also covers logout, and session caching
  (`get_session_state()`/`restore_session_state()`/`is_logged_in()`) so
  a repeatedly-invoked caller (a monitoring job run on a schedule) can
  skip the full login chain on every run.
- `EssentialController` - one organization's Essential Controller -
  sites, devices, clients, alert counts, dashboard overview. Obtained
  via `OmadaCloudAccount.essential_controller(org_id)`.

Verified live against a real "Omada Essential" free-tier account (one
organization, two sites, no MFA). See the module docstrings in
[src/omada_automata/account.py](src/omada_automata/account.py) and
[src/omada_automata/essential.py](src/omada_automata/essential.py) for
exactly what's confirmed vs assumed - in particular, `get_devices()`,
`get_clients()`, and `get_dashboard_overview()` return raw dicts/lists
rather than parsed dataclasses. Their shapes have now been confirmed
against a live account, just not yet turned into dataclasses.

Not covered yet: Omada Central (a separate dashboard product also seen
in the source capture), MFA/2FA-enabled accounts, and any
state-changing operations (this package is fetch-only).

## Install

See [INSTALL](INSTALL.md)

## Running tests

Tests are pure unit tests (no live account touched) - HTTP calls are
mocked with `requests-mock`, and response parsing is exercised against
fixtures under `tests/fixtures/` shaped to match a real captured
session, with account-identifying values replaced by placeholders.

```sh
uv sync --group dev  # or: pip install -e .[test]
uv run pytest        # or: pytest
```

## Examples

Minimal usage:
```python
import omada_automata

account = omada_automata.OmadaCloudAccount()
account.login('you@example.com', 'your-password')

orgs = account.list_organizations()
controller = account.essential_controller(orgs[0].org_id)

for site in controller.get_sites():
    print(site.name, controller.get_alert_count(site.site_id))
    devices = controller.get_devices(site.site_id)  # raw dict, shape unconfirmed
```

Caching a session across repeated runs (e.g. a monitoring job invoked
by cron, where logging in from scratch every time would be wasteful):
```python
account = omada_automata.OmadaCloudAccount()

cached_state = load_from_wherever_you_store_it()  # your own storage, not this package's concern
if cached_state:
    account.restore_session_state(cached_state)

if not account.is_logged_in():
    account.login('you@example.com', 'your-password')
    save_to_wherever_you_store_it(account.get_session_state())

# ... use account/controller as normal ...

account.logout()  # only when you actually want to end the session
```

[examples/walkthrough.py](examples/walkthrough.py) exercises every
fetch method currently in the package - login (with the session-cache
pattern above, cached to `examples/.omada_session.json`),
account/organization data, then sites/devices/clients/alerts/dashboard
for each site - against a real account, reading credentials from
`examples/.env` rather than hardcoding them:

```sh
cp examples/.env.example examples/.env   # then fill in OMADA_EMAIL/OMADA_PASSWORD
uv sync --group examples
uv run python examples/walkthrough.py           # logs in, or reuses the cached session
uv run python examples/walkthrough.py --logout  # logs out and removes the cache
```

`examples/.env` is gitignored (matches the repo-wide `.env` rule) -
never commit real credentials. `OMADA_ORG_ID`/`OMADA_SITE_ID` in that
file are optional - leave them blank to use the first organization/all
sites the account has access to. `examples/.omada_session.json` is
also gitignored - it holds a live session cookie/CSRF token, which is
as sensitive as a password.
