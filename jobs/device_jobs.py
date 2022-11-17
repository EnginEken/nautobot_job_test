from nautobot.extras.jobs import *

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