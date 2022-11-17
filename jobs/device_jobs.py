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


from device_filter import filter_devices


class NapalmGetJob(Job):
    class Meta:
        name = "Device Remove Flow Job"
        description = "Device removal"
    
    serial = StringVar()

    def run(self, data, commit):
        query, devices = filter_devices(data)
        self.log_warning(message=query)
        return devices