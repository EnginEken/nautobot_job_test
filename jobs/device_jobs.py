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
        "serial",
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
    # devices_no_platform = devices_filtered.qs.filter(platform__isnull=True)
    # if devices_no_platform.count() > 0:
    #     raise Exception(
    #         f"The following device(s) {', '.join([device.name for device in devices_no_platform])} have no platform defined. Platform is required."
    #     )

    return devices_filtered.qs


class NapalmGetJob(Job):
    class Meta:
        name = "Device Remove Flow Job"
        description = "Device removal"
    
    serial_number = StringVar()

    def run(self, data, commit):
        devices = filter_devices(data)
        return devices