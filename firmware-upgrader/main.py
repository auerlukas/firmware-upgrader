import logging
import re
import urllib3

from flask import Flask
from flask import render_template
from nornir.core import InitNornir
from nornir.plugins.tasks import networking
from nornir.plugins.tasks.networking import napalm_get
from nornir.plugins.functions.text import print_result

app = Flask(__name__)


def get_firmware_version(task):
    """
    runs napalm get_facts, extracts firmware version and saves it in the inventory
    as a host variable 'firmware'
    note: depending on the OS, napalm returns the 'os version' in different formats,
    somtimes just the version jumber (9.2(1)) and sometimes
    :param task:
    :return:
    """
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


@app.route("/")
def start():
    return render_template('index.html')


@app.route("/firmware")
def run_nornir():
    # nr = InitNornir(config_file='nornir/config.yaml')
    nr = InitNornir(config_file='nornir/config.yaml', dry_run=True)

    # apply filter to inventory
    cisco = nr.filter(site='cisco')

    # run task 'get_firmware_version'
    result = cisco.run(task=get_firmware_version)

    # show firmware versions
    devices = {}
    for h in cisco.inventory.hosts.keys():
        devices[cisco.inventory.hosts[h]['name']] = cisco.inventory.hosts[h]['firmware']
        # print('{h}: {f}'.format(h=cisco.inventory.hosts[h]['name'], f=cisco.inventory.hosts[h]['firmware']))

    return render_template('firmware.html', devices=devices)


if __name__ == '__main__':
    logging.basicConfig(filename='../log/app.log', level=logging.INFO)

    logging.debug('disabling InsecureRequestWarnings...')
    # suppress InsecureRequestWarnings
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    # run flask web app
    logging.info('starting web application..')
    app.run(debug=True)
    # run_nornir()
