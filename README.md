# Omada Automations

Automate login to TP-Link's Omada Cloud (id.tplinkcloud.com /
omada-cloud web UI) and fetch data from an "Omada Essential" cloud-
hosted controller - sites, devices, clients, alerts.

## Modules

- `OmadaCloudAccount` - unified-ID SSO login (email/password), plus
  Cloud Manager account/organization data (organization list,
  per-organization API hosts).
- `EssentialController` - one organization's Essential Controller -
  sites, devices, clients, alert counts, dashboard overview. Obtained
  via `OmadaCloudAccount.essential_controller(org_id)`.

Verified live against a real "Omada Essential" free-tier account (one
organization, two sites, no MFA). See the module docstrings in
[src/omada_automata/account.py](src/omada_automata/account.py) and
[src/omada_automata/essential.py](src/omada_automata/essential.py) for
exactly what's confirmed vs assumed - in particular, `get_devices()`,
`get_clients()`, and `get_dashboard_overview()` return raw dicts rather
than parsed dataclasses, because the response bodies for those
endpoints weren't captured in the HAR this was built from (only their
request shape and byte size were).

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

[examples/walkthrough.py](examples/walkthrough.py) exercises every
fetch method currently in the package - login, account/organization
data, then sites/devices/clients/alerts/dashboard for each site -
against a real account, reading credentials from `examples/.env`
rather than hardcoding them:

```sh
cp examples/.env.example examples/.env   # then fill in OMADA_EMAIL/OMADA_PASSWORD
uv sync --group examples
uv run python examples/walkthrough.py
```

`examples/.env` is gitignored (matches the repo-wide `.env` rule) -
never commit real credentials. `OMADA_ORG_ID`/`OMADA_SITE_ID` in that
file are optional - leave them blank to use the first organization/all
sites the account has access to.
