import re
import urllib3

from nornir.core import InitNornir
from nornir.plugins.tasks import networking
from nornir.plugins.tasks.networking import napalm_get
from nornir.plugins.functions.text import print_result


def get_firmware_version(task):
    # use napalm to get device facts
    r = task.run(task=networking.napalm_get, getters=['facts'])

    # extract OS version from result using regex
    os_version = r.result['facts']['os_version']
    # p = re.compile(r'(Version )(\d{2,}\.\d\.\d)', re.IGNORECASE)
    p = re.compile(r'(\d+.\d+(\(|\.)\d+[a-z]?(\)?))', re.IGNORECASE)
    matches = p.findall(os_version)
    # if version number could not be found using regex pattern: set firmware to 'unknown'
    if len(matches) == 0:
        firmware = 'unknown'
    # else: set firmware to version number
    else:
        firmware = matches[0][0]

    # save the firmware version into a host variable
    task.host['firmware'] = firmware


def run_nornir():
    # suppress InsecureRequestWarnings
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    # nr = InitNornir(config_file='nornir/config.yaml')
    nr = InitNornir(config_file='nornir/config.yaml', dry_run=True)

    # apply filter to inventory
    inv = nr.filter(site='cisco')

    # run task 'get_firmware_version'
    result = inv.run(task=get_firmware_version)

    # show firmware versions
    for h in inv.inventory.hosts.keys():
        print('{h}: {f}'.format(h=inv.inventory.hosts[h]['name'],f=inv.inventory.hosts[h]['firmware']))


if __name__ == '__main__':
    run_nornir()
