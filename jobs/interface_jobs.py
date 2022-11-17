from nautobot.dcim.models import (
    Device,
    DeviceType,
    Manufacturer,
    Region,
    RackGroup,
    Rack,
    Site,
    DeviceRole,
    Platform,
    Interface,
)
from nautobot.tenancy.models import TenantGroup, Tenant
from nautobot.extras.models import Status, Tag, CustomField
from nautobot.extras.jobs import *
from nautobot.extras.choices import (
    SecretsGroupAccessTypeChoices,
    SecretsGroupSecretTypeChoices,
)
from nautobot.extras.secrets.exceptions import SecretError
from nautobot.dcim.filters import DeviceFilterSet

from django.conf import settings
from django.core.exceptions import ObjectDoesNotExist

from device_filter import filter_devices
import socket
import re


def filter_devices(data):
    """
    * Getting TreeQuerySet and RestrictedQuerySet values as data chosen from FormEntry and
    filter all devices based on data values.
    * Filtering can be done with AND or OR operator based on the selecetion of filter_type.
    """
    FIELDS = {
        "tenant_group",
        "tenant",
        "region",
        "site",
        "rack",
        "rack_group",
        "role",
        "platform",
        "device_type",
        "status",
        "manufacturer",
        "tags",
    }
    query = {}
    for field in FIELDS:
        if data.get(field):
            query[f"{field}_id"] = data[field].values_list("pk", flat=True)
    # Handle case where object is from single device run all.
    if data.get("device") and isinstance(data["device"], Device):
        query.update({"id": [str(data["device"].pk)]})
    elif data.get("device"):
        query.update({"id": data["device"].values_list("pk", flat=True)})

    base_qs = Device.objects.all()

    if base_qs.count() == 0:
        raise Exception(
            "The base queryset didn't find any devices. Please check the Setting scope."
        )
    devices_filtered = DeviceFilterSet(data=query, queryset=base_qs)
    if devices_filtered.qs.count() == 0:
        raise Exception(
            "The provided job parameters didn't match any devices detected by the scope. Please check the scope defined within Settings or select the correct job parameters to correctly match devices."
        )
    devices_no_platform = devices_filtered.qs.filter(platform__isnull=True)
    if devices_no_platform.count() > 0:
        raise Exception(
            f"The following device(s) {', '.join([device.name for device in devices_no_platform])} have no platform defined. Platform is required."
        )

    return devices_filtered.qs


class FormEntry:
    """
    Form class for the filter fields on nautobot. These field types are provided with nautobot Job class
    query_params value in the fields used for instant filtering on other field's selection
    """

    tenant = MultiObjectVar(model=Tenant, required=False)
    tenant_group = MultiObjectVar(model=TenantGroup, required=False)
    site = MultiObjectVar(
        model=Site,
        required=False,
        query_params={
            "region_id": "$region",
            "tenant_group_id": "$tenant_group",
        },
    )
    region = MultiObjectVar(
        model=Region, required=False, query_params={"site_id": "$site"}
    )
    rack_group = MultiObjectVar(
        model=RackGroup,
        required=False,
        query_params={"region_id": "$region", "site_id": "$site"},
    )
    rack = MultiObjectVar(
        model=Rack,
        required=False,
        query_params={
            "site_id": "$site",
            "region_id": "$region",
            "rack_group_id": "$rack_group",
        },
    )
    role = MultiObjectVar(model=DeviceRole, required=False)
    platform = MultiObjectVar(
        model=Platform,
        required=False,
        query_params={
            "manufacturer_id": "$manufacturer",
            "device_type_id": "$device_type",
            "role_id": "$role",
        },
    )
    device_type = MultiObjectVar(
        model=DeviceType,
        required=False,
        display_field="display",
        query_params={
            "platform_id": "$platform",
            "status_id": "$status",
            "manufacturer_id": "$manufacturer",
        },
    )
    manufacturer = MultiObjectVar(
        model=Manufacturer,
        required=False,
        query_params={"platform_id": "$platform", "device_type_id": "$device_type"},
    )
    status = MultiObjectVar(model=Status, required=False)
    tag = MultiObjectVar(model=Tag, required=False)
    device = MultiObjectVar(
        model=Device,
        required=False,
        query_params={
            "tenant_id": "$tenant",
            "tenant_group_id": "$tenant_group",
            "site_id": "$site",
            "region_id": "$region",
            "rack_id": "$rack",
            "rack_group_id": "$rack_group",
            "role_id": "$role",
            "platform_id": "$platform",
            "device_type_id": "$device_type",
            "manufacturer_id": "$manufacturer",
            "status_id": "$status",
        },
    )
    napalm_method = ChoiceVar(
        description="Napalm Get Method",
        choices=(
            ("get_lldp_neighbors_detail", "get_lldp_neighbors_detail"),
            ("get_facts", "get_facts"),
        ),
    )
    interface_regex = StringVar(
        required=False,
        description="Regular expression to filter interfaces",
    )
    interfaces = MultiObjectVar(
        model=Interface,
        required=False,
        query_params={
            "device_id": "$device",
            # Filtering interfaces with the given regex value in interface_regex variable.
            # https://nautobot.readthedocs.io/en/latest/rest-api/filtering/ filter methods in this link can be used for table fields like below
            "name__re": "$interface_regex",
        },
    )
    interface_role = ChoiceVar(
        choices=(
            choice
            for choice in CustomField.objects.filter(name="intf_role")[0]
            .to_form_field()
            .choices
        )
    )


class NapalmGetJob(Job):
    class Meta:
        name = "LLDP-Nautobot Interface Info Comparison"
        description = "Get Napalm Methods Info from the devices with the given filters and compare them with the configured interface information in Nautobot"

    tenant_group = FormEntry.tenant_group
    tenant = FormEntry.tenant
    region = FormEntry.region
    site = FormEntry.site
    rack_group = FormEntry.rack_group
    rack = FormEntry.rack
    role = FormEntry.role
    manufacturer = FormEntry.manufacturer
    platform = FormEntry.platform
    device_type = FormEntry.device_type
    device = FormEntry.device
    status = FormEntry.status
    tag = FormEntry.tag
    napalm_method = FormEntry.napalm_method

    def get_napalm_credentials(self, device):
        if device.secrets_group:
            try:
                try:
                    napalm_username = device.secrets_group.get_secret_value(
                        SecretsGroupAccessTypeChoices.TYPE_GENERIC,
                        SecretsGroupSecretTypeChoices.TYPE_USERNAME,
                        obj=device,
                    )
                except ObjectDoesNotExist:
                    # No defined secret, fall through to legacy behavior
                    napalm_username = settings.NAPALM_USERNAME
                try:
                    napalm_password = device.secrets_group.get_secret_value(
                        SecretsGroupAccessTypeChoices.TYPE_GENERIC,
                        SecretsGroupSecretTypeChoices.TYPE_PASSWORD,
                        obj=device,
                    )
                except ObjectDoesNotExist:
                    # No defined secret, fall through to legacy behavior
                    napalm_password = settings.NAPALM_PASSWORD
            except SecretError as exc:
                self.log_warning(
                    obj=device,
                    message=f"Unable to retrieve device credentials: {exc.message}",
                )
                # pass
        else:
            napalm_username = settings.NAPALM_USERNAME
            napalm_password = settings.NAPALM_PASSWORD

        optional_args = settings.NAPALM_ARGS.copy()
        if device.platform.napalm_args is not None:
            optional_args.update(device.platform.napalm_args)

        # Get NAPALM enable-secret from the device if present
        if device.secrets_group:
            # Work around inconsistent enable password arg in NAPALM drivers
            enable_password_arg = "secret"
            if device.platform.napalm_driver.lower() == "eos":
                enable_password_arg = "enable_password"
            try:
                optional_args[
                    enable_password_arg
                ] = device.secrets_group.get_secret_value(
                    SecretsGroupAccessTypeChoices.TYPE_GENERIC,
                    SecretsGroupSecretTypeChoices.TYPE_SECRET,
                    obj=device,
                )
            except ObjectDoesNotExist:
                # No defined secret, this is OK
                pass
            except SecretError as exc:
                self.log_warning(
                    obj=device,
                    message=f"Unable to retrieve device credentials: {exc.message}",
                )

        return napalm_username, napalm_password, optional_args

    def compare_lldp_nautobot(self, device, lldp_results_device):
        compare_results_device = {}
        if not "error" in lldp_results_device:
            for nautobot_interface in device.interfaces.all():
                if nautobot_interface.enabled:
                    interface_name = nautobot_interface.name
                    compare_results_device[interface_name] = {}
                    compare_results_device[interface_name]["is_enabled"] = True
                    if interface_name in lldp_results_device:
                        if nautobot_interface.cable:
                            compare_results_device[interface_name]["has_cabling"] = True
                            if (
                                nautobot_interface.cable.termination_a.device.name
                                == re.split(
                                    "\.",
                                    lldp_results_device[interface_name][0][
                                        "remote_system_name"
                                    ],
                                )[0]
                                or nautobot_interface.cable.termination_b.device.name
                                == re.split(
                                    "\.",
                                    lldp_results_device[interface_name][0][
                                        "remote_system_name"
                                    ],
                                )[0]
                            ):
                                # Bazı cihazların bazı connectionlarında karşı taraf termination_a olarak bazı connectionlarında ise termination_b olarak girilmiş. Örn cihaz: DCIRTR-ES-H4-RZDJ72-WED-P0-N02
                                # O yüzden lldp bilgisinde yer alan remote_system_name bilgisi hem termination_a hem de termination_b ile karşılaştırılmak durumunda kalınmıştır.
                                compare_results_device[interface_name][
                                    "lldp_match_with_nautobot"
                                ] = True
                                self.log_success(
                                    obj=device,
                                    message=f"Interface: {interface_name}, is_enabled: {compare_results_device[interface_name]['is_enabled']}, \
                                        has_cabling: {compare_results_device[interface_name]['has_cabling']}, \
                                        does_lldp_match_with_nautobot_connection: {compare_results_device[interface_name]['lldp_match_with_nautobot']}, \
                                        lldp_remote_system_name: {lldp_results_device[interface_name][0]['remote_system_name']}",
                                )
                                lldp_results_device.pop(interface_name)
                            else:
                                compare_results_device[interface_name][
                                    "lldp_match_with_nautobot"
                                ] = False
                                compare_results_device[interface_name][
                                    "lldp_neighbor_info"
                                ] = lldp_results_device[interface_name][0]
                                self.log_failure(
                                    obj=device,
                                    message=f"Interface: {interface_name}, is_enabled: {compare_results_device[interface_name]['is_enabled']}, \
                                        has_cabling: {compare_results_device[interface_name]['has_cabling']}, \
                                        does_lldp_match_with_nautobot_connection: {compare_results_device[interface_name]['lldp_match_with_nautobot']}, \
                                        lldp_remote_system_name: {lldp_results_device[interface_name][0]['remote_system_name']}",
                                )
                        else:
                            compare_results_device[interface_name][
                                "has_cabling"
                            ] = False
                            compare_results_device[interface_name][
                                "has_lldp_neighbor"
                            ] = True
                            compare_results_device[interface_name][
                                "lldp_neighbor_info"
                            ] = lldp_results_device[interface_name][0]
                            self.log_warning(
                                obj=device,
                                message=f"Interface: {interface_name}, is_enabled: {compare_results_device[interface_name]['is_enabled']}, \
                                    has_cabling: {compare_results_device[interface_name]['has_cabling']}, \
                                    has_lldp_neighbor: {compare_results_device[interface_name]['has_lldp_neighbor']}, \
                                    lldp_remote_system_name: {lldp_results_device[interface_name][0]['remote_system_name']}",
                            )
                    else:
                        compare_results_device[interface_name][
                            "has_lldp_neighbor"
                        ] = False
                        if nautobot_interface.cable:
                            compare_results_device[interface_name]["has_cabling"] = True
                            self.log_info(
                                obj=device,
                                message=f"Interface: {interface_name}, is_enabled: {compare_results_device[interface_name]['is_enabled']}, \
                                        has_cabling: {compare_results_device[interface_name]['has_cabling']} \
                                        has_lldp_neighbor: {compare_results_device[interface_name]['has_lldp_neighbor']}",
                            )
                        else:
                            compare_results_device[interface_name][
                                "has_cabling"
                            ] = False
                            self.log_info(
                                obj=device,
                                message=f"Interface: {interface_name}, is_enabled: {compare_results_device[interface_name]['is_enabled']}, \
                                        has_cabling: {compare_results_device[interface_name]['has_cabling']} \
                                        has_lldp_neighbor: {compare_results_device[interface_name]['has_lldp_neighbor']}",
                            )
        return compare_results_device, lldp_results_device

    def run(self, data, commit=False):

        # Get Devices with specific filters and run the napalm command on these devices
        devices = filter_devices(data)
        if devices:
            self.log_info(
                obj=None, message=f"Devices are filtered based on given filters."
            )
        else:
            self.log_warning(
                obj=None, message=f"There is no device with the given filters."
            )

        lldp_results, compare_results = {}, {}

        for device in devices:

            # Check if device platform and napalm_driver is configured
            if device.platform is None:
                self.log_warning(
                    obj=device,
                    message=f"No platform is configured for this device: {device.name}.",
                )
                continue

            if not device.platform.napalm_driver:
                self.log_warning(
                    obj=device,
                    message=f"No NAPALM driver is configured for this device's platform: {device.platform}.",
                )
                continue

            # Check for primary IP address from Nautobot object
            if device.primary_ip:
                host = str(device.primary_ip.address.ip)
            else:
                # Raise exception for no IP address and no Name if device.name does not exist
                self.log_warning(
                    obj=device,
                    message=f"Can not be found configured IP address for this device: {device.name}. Trying resolving IP address with device name...",
                )

                if not device.name:
                    self.log_warning(
                        obj=device,
                        message=f"This {device.name} does not have a primary IP address or device name to lookup configured.",
                    )
                    continue
                try:
                    # Attempt to complete a DNS name resolution if no primary_ip is set
                    host = socket.gethostbyname(device.name)
                except socket.gaierror:
                    # Name lookup failure
                    self.log_warning(
                        obj=device,
                        message=f"Name lookup failure, unable to resolve IP address for {device.name}. Please set Primary IP or setup name resolution.",
                    )
                    continue

            # Check that NAPALM is installed
            try:
                import napalm
                from napalm.base.exceptions import ModuleImportError
            except ModuleNotFoundError as e:
                if getattr(e, "name") == "napalm":
                    self.log_warning(
                        obj=device,
                        message="NAPALM is not installed. Please see the documentation for instructions.",
                    )
                    continue
                pass

            # Validate the configured driver
            try:
                driver = napalm.get_network_driver(device.platform.napalm_driver)
            except ModuleImportError:
                self.log_warning(
                    obj=device,
                    message=f"NAPALM driver for platform {device.platform} not found: {device.platform.napalm_driver}.",
                )
                continue

            # Get NAPALM credentials for the device, or fall back to the legacy global NAPALM credentials
            (
                napalm_username,
                napalm_password,
                optional_args,
            ) = self.get_napalm_credentials(device)

            # Connect to the device
            d = driver(
                hostname=host,
                username=napalm_username,
                password=napalm_password,
                timeout=settings.NAPALM_TIMEOUT,
                optional_args=optional_args,
            )
            try:
                d.open()
            except Exception as e:
                self.log_failure(
                    obj=device,
                    message=f"Error connecting to the device {host} -- {device.name}: {e}",
                )
                continue

            if not hasattr(driver, data["napalm_method"]):
                self.log_failure(obj=device, message="Unknown NAPALM method")
                continue
            if not data["napalm_method"].startswith("get_"):
                self.log_failure(
                    obj=device, message="Only get_* NAPALM methods are supported"
                )
                continue
            try:
                lldp_results[host] = getattr(d, data["napalm_method"])()
            except NotImplementedError:
                self.log_failure(
                    obj=device,
                    message=f"Method {data['napalm_method']} not implemented for NAPALM driver {driver}",
                )
                continue
            except Exception as e:
                self.log_failure(
                    obj=device, message=f"Method {data['napalm_method']} failed: {e}"
                )
                continue

            d.close()

            # Comparison between lldp results and configured interfaces in nautobot manually
            compare_results[host], lldp_results[host] = self.compare_lldp_nautobot(
                device, lldp_results[host]
            )

        self.log_success(obj=None, message=f"Job is executed successfully")
        return lldp_results


class InterfaceRoleUpdateJob(Job):
    class Meta:
        name = "Interface Role Edit"
        description = "Edit interfaces role for the filtered Device(s)"
        commit_default = False

    tenant_group = FormEntry.tenant_group
    tenant = FormEntry.tenant
    region = FormEntry.region
    site = FormEntry.site
    rack_group = FormEntry.rack_group
    rack = FormEntry.rack
    role = FormEntry.role
    manufacturer = FormEntry.manufacturer
    platform = FormEntry.platform
    device_type = FormEntry.device_type
    device = FormEntry.device
    interface_regex = FormEntry.interface_regex
    interfaces = FormEntry.interfaces
    interface_role = FormEntry.interface_role
    status = FormEntry.status
    tag = FormEntry.tag

    def filter_interfaces(self, data, devices):
        """
        Fitering interfaces based on given regex for each device
        """
        interfaces = []
        for device in devices:
            for interface in device.interfaces.all():
                if re.match(data["interface_regex"], interface.name):
                    interfaces.append(interface)
        return interfaces

    def run(self, data, commit):

        interfaces = []
        devices = filter_devices(data)
        if (data["interface_regex"] and data["interfaces"]) or (
            not data["interface_regex"] and data["interfaces"]
        ):
            interfaces = data["interfaces"]
        elif data["interface_regex"] and not data["interfaces"]:
            interfaces = self.filter_interfaces(data, devices)
        else:
            self.log_failure(
                obj=None,
                message="You need to choose at least one interface to edit interface role",
            )

        for interface in interfaces:
            try:
                interface.custom_field_data["intf_role"] = data["interface_role"]
                interface.validated_save()
                self.log_success(
                    obj=interface, message="Interface role updated successfully."
                )
            except Exception as e:
                self.log_warning(
                    obj=interface, message=f"Interface role can not be updated! {e}"
                )
        return interfaces
