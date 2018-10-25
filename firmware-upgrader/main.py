import json
import logging
import re
import sys
import urllib3

import openVulnQuery
# from openVulnQuery.query_client import OpenVulnQueryClient
# from openVulnQuery.advisory import AdvisoryIOS
from typing import List

from flask import Flask
from flask import render_template
from nornir.core import InitNornir
from nornir.plugins.tasks import networking
from nornir.plugins.tasks.networking import napalm_get
from nornir.plugins.functions.text import print_result
app = Flask(__name__)


def find_vulnerabilities(version: str) -> List[openVulnQuery.advisory.AdvisoryIOS]:
    """
    finds all vulnerabilities of a given Cisco switch model by querying the Cisco openvuln API
    (only works for devices running IOS since function 'get_by_ios' is being used
    :param version: Cisco switch model running IOS
    :return: returns a list of all found vulnerabilities
    """
    try:
        with(open('openvuln/openvuln_api_credentials.json', 'r')) as data:
            credentials = json.load(data)
    except FileNotFoundError as e:
        print('file with openvuln api credentials could not be found!\n{e}'.format(e=e), file=sys.stderr)
        sys.exit(1)

    openVulnQuery.query_client.OpenVulnQueryClient
    query_client: openVulnQuery.query_client.OpenVulnQueryClient = openVulnQuery.query_client.OpenVulnQueryClient(client_id=credentials['CLIENT_ID'],
                                                            client_secret=credentials['CLIENT_SECRET'])
    advisories: List[openVulnQuery.advisory.AdvisoryIOS] = query_client.get_by_ios('', version)
    return advisories


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


@app.route("/inventory")
def inventory():
    return render_template('inventory.html')


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


@app.route("/vulnerabilities")
def vulnerabilities():
    version = '12.2(55)SE11'
    vulnerabilities = find_vulnerabilities(version)
    return render_template('vulnerabilities.html', vulnerabilities=vulnerabilities)


if __name__ == '__main__':
    print("PATH: ")
    print(sys.path)
    logging.basicConfig(filename='../log/app.log', level=logging.INFO)

    logging.debug('disabling InsecureRequestWarnings...')
    # suppress InsecureRequestWarnings
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    # run flask web app
    logging.info('starting web application..')
    app.run(debug=True)
    # run_nornir()
