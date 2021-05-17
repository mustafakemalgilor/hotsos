#!/usr/bin/python3
import re
import os

from common import (
    constants,
    cli_helpers,
    plugin_yaml,
)


SYSTEM_INFO = {}


class SystemChecks(object):

    @property
    def unattended_upgrades_enabled(self):
        apt_config_dump = cli_helpers.get_apt_config_dump()
        if not apt_config_dump:
            return

        for line in apt_config_dump:
            ret = re.compile(r"^APT::Periodic::Unattended-Upgrade\s+"
                             "\"([0-9]+)\";").match(line)
            if ret:
                if int(ret[1]) == 0:
                    return False
                else:
                    return True

        return False

    def get_system_info(self):
        hostname = cli_helpers.get_hostname()
        if hostname:
            hostname = hostname[0].split()[0]
        else:
            hostname = "unavailable"

        SYSTEM_INFO["hostname"] = hostname

        data_source = os.path.join(constants.DATA_ROOT, "etc/lsb-release")
        if os.path.exists(data_source):
            for line in open(data_source).read().split():
                ret = re.compile(r"^DISTRIB_CODENAME=(.+)").match(line)
                if ret:
                    SYSTEM_INFO["os"] = "ubuntu {}".format(ret[1])
                    break

        lscpu_output = cli_helpers.get_lscpu()
        if lscpu_output:
            for line in lscpu_output:
                ret = re.compile(r"^CPU\(s\):\s+([0-9]+)\s*.*").match(line)
                if ret:
                    SYSTEM_INFO["num-cpus"] = int(ret[1])
                    break

        uptime_output = cli_helpers.get_uptime()
        if uptime_output:
            for line in uptime_output:
                ret = re.compile(r".+load average:\s+(.+)").match(line)
                if ret:
                    SYSTEM_INFO["load"] = ret[1]
                    break
        df_output = cli_helpers.get_df()
        if df_output:
            for line in df_output:
                ret = re.compile(r"(.+\/$)").match(line)
                if ret:
                    SYSTEM_INFO["rootfs"] = ret[1]
                    break

        if self.unattended_upgrades_enabled:
            SYSTEM_INFO['unattended-upgrades'] = "ENABLED"
        else:
            SYSTEM_INFO['unattended-upgrades'] = "disabled"

    def __call__(self):
        self.get_system_info()


def get_system_checks():
    # do this way to facilitate unit tests
    return SystemChecks()


if __name__ == "__main__":
    get_system_checks()()
    if SYSTEM_INFO:
        plugin_yaml.save_part(SYSTEM_INFO, priority=0)
