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
        "serial"
    }
    query = {}
    for field in FIELDS:
        if data.get(field):
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


    return query, devices_filtered.qs

def filter_devices(data):
    """
    * Getting TreeQuerySet and RestrictedQuerySet values as data chosen from FormEntry and
    filter all devices based on data values.
    * Filtering can be done with AND or OR operator based on the selecetion of filter_type.
    """
    devices_filtered = Device.objects.filter(serial=data["serial_number"])
    # self.log_warning(
    #                 obj=device,
    #                 message=f"Unable to retrieve device credentials: {exc.message}",
    #             )
    return devices_filtered


class NapalmGetJob(Job):
    class Meta:
        name = "Device Remove Flow Job"
        description = "Device removal"
    
    serial = StringVar()

    def run(self, data, commit):
        query, devices = filter_devices(data)
        self.log_warning(message=query)
        return devices