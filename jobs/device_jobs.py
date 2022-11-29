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

import socket
import re

def filter_devices(data):
    """
    * Getting TreeQuerySet and RestrictedQuerySet values as data chosen from FormEntry and
    filter all devices based on data values.
    * Filtering can be done with AND or OR operator based on the selecetion of filter_type.
    """
    FIELDS = {
        # "tenant_group",
        # "tenant",
        # "region",
        # "site",
        # "rack",
        # "rack_group",
        # "role",
        # "platform",
        # "device_type",
        # "status",
        # "manufacturer",
        # "tags",
        "serial"
    }
    query = {}
    for field in FIELDS:
        if data.get(field):
            if hasattr(data[field], 'values_list'):
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


class DeviceMoveJob(Job):
    class Meta:
        name = "Device Move"
        description = "Job for changing device site/rack"
    
    serial = StringVar()
    destination_site = MultiObjectVar(
        model=Site,
        required=False,
        query_params={
            "region_id": "$region",
            "tenant_group_id": "$tenant_group",
        },
    )

    def run(self, data, commit):
        devices = filter_devices(data)
        if devices.count() >= 1:
            self.log_warning(message=f"Found more than 1 device. Using first one.")
            device = devices[0]
        elif devices.count() == 0:
            self.log_failure(message=f"No device found with the given serial number")
            raise Exception(
                "No device found with the given serial number"
            )
        else:
            device = devices[0]
        dest_site = Site.objects.get(id=data['destination_site'])
        self.log_warning(f"current device site {device.site.name}")
        device.site = dest_site
        device.site.validated_save()
        self.log_warning(f"Changed site {device.site.name}")
        return device.site