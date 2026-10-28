'''Structured views of the API responses whose full shape was actually
confirmed against a live capture (see account.py/essential.py module
docstrings for which endpoints that covers). Endpoints whose response
body wasn't captured are returned as raw dicts instead of being forced
into a dataclass here - see get_devices()/get_clients()/
get_dashboard_overview() in essential.py.
'''
from __future__ import annotations

import dataclasses


@dataclasses.dataclass
class Organization:
    '''One entry from Cloud Manager's organization-list.'''
    org_id: str
    name: str
    category: str
    site_num: int
    role: int
    msp_mode: bool
    central_enable: bool
    network_enable: bool
    surveillance_enable: bool


@dataclasses.dataclass
class OrganizationHosts:
    '''Per-organization regional API base URLs (account/{org}/hosts) -
    each product an organization can have enabled gets its own base
    URL, which can differ in region from the account's own Cloud
    Manager host. Any product not enabled for this organization is
    None rather than an empty string.
    '''
    omada: str | None
    essential: str | None
    central: str | None
    vms: str | None
    redirect_url: str | None


@dataclasses.dataclass
class OnPremiseControllerSummary:
    '''One entry from Cloud Access's cloudaccess/organizations list -
    an on-premise hardware controller (e.g. an OC200) this account can
    reach remotely through TP-Link's cloud proxy. Pass `device_id` to
    OmadaCloudAccount.onpremise_controller() to connect to one.
    '''
    device_id: str
    alias: str
    status: int
    device_mac: str
    device_model: str
    device_hw_ver: str
    show_model: str
    controller_version: str
    fw_ver: str
    ip: str
    sites: int
    devices: int
    clients: int
    alerts: int
    category: str
    sn: str
    app_server_url: str
    connector_url: str
    omadac_id: str
    mfa_status: bool


@dataclasses.dataclass
class Site:
    '''One entry from the Essential Controller's user/sites.'''
    site_id: str
    name: str
    favorite: bool


@dataclasses.dataclass
class SitePrivilege:
    '''The current user's site access (current/user-detail's
    sitePrivilege block) - `all_sites=True` means every site in the
    organization, regardless of what's listed in site_ids.
    '''
    all_sites: bool
    service_type: int
    site_ids: list[str]


@dataclasses.dataclass
class CurrentUser:
    '''The logged-in user, from the Essential Controller's
    current/user-detail.'''
    user_id: str
    email: str
    name: str
    role_id: str
    role_name: str
    user_level: int
    site_privilege: SitePrivilege
