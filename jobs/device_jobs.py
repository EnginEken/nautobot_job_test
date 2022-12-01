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
)
from nautobot.ipam.models import IPAddress
from nautobot.tenancy.models import TenantGroup, Tenant
from nautobot.extras.models import Status, Tag
from nautobot.extras.jobs import *

from nautobot.dcim.filters import DeviceFilterSet

from nautobot.utilities.forms import APISelect

from django.core.exceptions import ValidationError


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
        "serial",
    }
    query = {}
    for field in FIELDS:
        if data.get(field):
            if hasattr(data[field], "values_list"):
                query[f"{field}_id"] = data[field].values_list("pk", flat=True)
            else:
                query[f"{field}"] = data[field]
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
    serial = StringVar()
    position = IntegerVar(
        required=False,
        widget=APISelect(
            api_url="/api/dcim/racks/{{destination_rack}}/elevation/",
            attrs={
                "disabled-indicator": "device",
            },
        ),
    )


class DeviceDetailChecker(Job):
    class Meta:
        name = "Device detail checker"
        description = "Check device details such as serial number, IP address, etc"
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
    status = FormEntry.status
    tag = FormEntry.tag

    def null_serial(self, devices):
        return devices.filter(serial="").all()

    def dup_serial(self, devices):
        seen = dict()
        for device in devices.exclude(serial__isnull=True).exclude(serial="").all():
            serial = device.serial
            if serial in seen:
                seen[serial].append(device)
            else:
                seen[serial] = [device]
        # return [d for k, v in seen.items() if len(v) > 1 for d in v]
        return {k: v for k, v in seen.items() if len(v) > 1}

    def null_rack_position(self, devices):
        return devices.filter(position__isnull=True).all()

    def null_rack(self, devices):
        return devices.filter(rack__isnull=True).all()

    def null_primary_ip(self, devices):
        return devices.filter(primary_ip4__isnull=True).all()

    def null_interface_vrf(self, devices):
        missing_vrf = []
        for device in devices.all():
            for interface in device.interfaces.all():
                for ip_address in interface.ip_addresses.all():
                    if ip_address.vrf is None:
                        missing_vrf.append((device, interface, ip_address))
        return missing_vrf

    def dup_ip_address(self):
        seen = dict()
        for ip_address in IPAddress.objects.all():
            ip = str(ip_address)
            if ip in seen:
                seen[ip].append(ip_address)
            else:
                seen[ip] = [ip_address]
        # return [d for k, v in seen.items() if len(v) > 1 for d in v]
        return {k: v for k, v in seen.items() if len(v) > 1}

    def run(self, data, commit=False):
        filtered_devices = filter_devices(data)
        self.log("Listing devices without serial number")
        for dev in self.null_serial(filtered_devices):
            self.log_warning(dev, "Missing serial number")
        self.log("Listing devices without rack")
        for dev in self.null_rack(filtered_devices):
            self.log_warning(dev, "Missing rack")
        self.log("Listing devices without rack position")
        for dev in self.null_rack_position(filtered_devices):
            self.log_warning(dev, "Missing rack position")
        self.log("Listing devices with duplicate serial numbers")
        for serial, device_list in self.dup_serial(filtered_devices).items():
            self.log(
                f"{[dev for dev in device_list]} shares the same serial number: {serial}"
            )
            for dev in device_list:
                self.log_warning(dev, f"has serial number: {serial}")
        self.log("Listing device interface ip addresses didn't attached to a vrf")
        for dev, intf, ip_addr in self.null_interface_vrf(filtered_devices):
            self.log_warning(intf, f"{dev}-{intf}-{ip_addr} is not attached to a vrf")
        # self.log("Listing duplicated IP Addresses")
        # for ip_addr, obj in self.dup_ip_address().items():
        #     self.log_warning(obj, f"{ip_addr} is a duplicated address")


class DeviceMover(Job):
    class Meta:
        name = "Device Location Changer"
        description = "Job for changing device site/rack/position"

    serial = FormEntry.serial
    destination_site = ObjectVar(
        model=Site,
        required=False,
    )
    destination_rack = ObjectVar(
        model=Rack,
        required=False,
        query_params={
            "site_id": "$destination_site",
        },
    )
    destination_u = FormEntry.position

    _INVENTORY_ROLE_ID = "37b7b3c9-20d0-4d17-bab4-221f79d94be4" # Şu an test nautobotu için id bu. Prod a alırken proddan almak gerekiyor.
    _STATUS_INVENTORY_ID = "019b2a93-3e3f-4ed9-92c4-ce5da0729348"

    def run(self, data, commit):
        
        devices = filter_devices(data)
        
        if devices.count() > 1:
            self.log_info(message=f"Found more than 1 device. Using first one.")
            device = devices[0]
        
        elif devices.count() == 0:
            self.log_failure(message=f"No device found with the given serial number")
            raise Exception("No device found with the given serial number")
        
        else:
            self.log_info(message=f"Found 1 device with given serial number.")
            device = devices[0]

        dest_site = Site.objects.get(id=data["destination_site"].id)
        dest_rack = Rack.objects.get(id=data["destination_rack"].id)
        dest_position = data["destination_u"]
        is_inventory_item = True if 'STR' in dest_site.name else False
        
        if is_inventory_item:
            device.clean()

            self.log_info(message=f"Setting device site to {dest_site}")
            device.site = dest_site
            
            self.log_info(message=f"Setting device rack to {dest_rack}")
            device.rack = dest_rack
            
            self.log_info(message=f"Setting device position to U{data['destination_u']}")
            device.position = dest_position

            # device.name = ""
            # device.role = DeviceRole.objects.get(id=self._INVENTORY_ROLE_ID)
            # device.status = Status.objects.get(id=self._STATUS_INVENTORY_ID)
            # device.asset_tag = ""
            # device.tenant = None
            # device.primary_ip4 = None
            # device.secrets_group = None
            # device.cluster = None
            # device.virtual_chassis = None
        try:
            device.validated_save()
        
        except ValidationError as err:
            self.log_failure(f"Device Validation Error: {err}")
            raise err
        
        self.log_success(obj=device, message=f"Device location changed successfully!")
        
        return device.site, device.rack, device.position
