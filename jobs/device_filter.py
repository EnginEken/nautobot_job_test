from nautobot.dcim.models import Device
from nautobot.dcim.filters import DeviceFilterSet

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


    return query, devices_filtered.qs