import json
import logging
import re
import sys
import urllib3
import yaml

import openVulnQuery
# from openVulnQuery.query_client import OpenVulnQueryClient
# from openVulnQuery.advisory import AdvisoryIOS
from typing import List

from flask import Flask
from flask import render_template
from flask import request
from nornir.core import InitNornir
from nornir.plugins.tasks import networking
from nornir.plugins.tasks.networking import napalm_get
from nornir.plugins.functions.text import print_result

app = Flask(__name__)


# @TODO comments/documentation
# @TODO type hinting
# @TODO logging
# @TODO unit tests
# @TODO queueing
# @TODO interface with netbox
# @TODO methoden in eigenes file auslagern


# ##################################################################################################
# ##################################################################################################
#                                                                                                  #
# FLASK ROUTES                                                                                     #
#                                                                                                  #
# ##################################################################################################
# ##################################################################################################
@app.route("/")
def start():
    return render_template('index.html')


@app.route("/inventory")
def inventory_index():
    devices = get_all_devices()
    return render_template('inventory/index.html', devices=devices)


@app.route("/firmware")
def firmware_index():
    return render_template('firmware/index.html')


@app.route("/firmware/show")
def firmware_show():
    devices = get_firmware()
    return render_template('firmware/show.html', devices=devices)


@app.route("/vulnerabilities")
def vulnerabilities_index():
    return render_template('vulnerabilities/index.html')


@app.route("/vulnerabilities/show")
def vulnerabilities_show() -> List[openVulnQuery.advisory.AdvisoryIOS]:
    os = request.args.get('os')
    version = request.args.get('version')

    vulnerabilities = find_vulnerabilities(os, version)
    return render_template('vulnerabilities/show.html', vulnerabilities=vulnerabilities, os=os, version=version)


def find_vulnerabilities(os: str = '', version: str = '') -> List[openVulnQuery.advisory.AdvisoryIOS]:
    """
    finds all vulnerabilities of a given Cisco switch model by querying the Cisco openvuln API
    (only works for devices running IOS since function 'get_by_ios' is being used
    :param version: Cisco switch model running IOS
    :return: returns a list of all found vulnerabilities
    """
    if os == '':
        os = request.args.get('os')
    if version == '':
        version = request.args.get('version')

    try:
        with(open('openvuln/openvuln_api_credentials.json', 'r')) as data:
            credentials = json.load(data)
    except FileNotFoundError as e:
        print('file with openvuln api credentials could not be found!\n{e}'.format(e=e), file=sys.stderr)
        sys.exit(1)

    query_client: openVulnQuery.query_client.OpenVulnQueryClient = openVulnQuery.query_client.OpenVulnQueryClient(
        client_id=credentials['CLIENT_ID'],
        client_secret=credentials['CLIENT_SECRET'])

    if os == 'ios':
        advisories: List[openVulnQuery.advisory.AdvisoryIOS] = query_client.get_by_ios('', version)
    elif os == 'ios-xe':
        advisories: List[openVulnQuery.advisory.AdvisoryIOS] = query_client.get_by_ios_xe('', version)
    return advisories


def get_all_devices() -> dict:
    """
    reads the devices.yaml in the inventory directory
    :return: returns a dictionary of all devices in the inventory
    """
    try:
        stream = open('inventory/devices.yaml')
    except FileNotFoundError as e:
        print('inventory file could not be found!\n{e}'.format(e=e), file=sys.stderr)
        sys.exit(1)

    devices = yaml.load(stream)
    return devices


# this method is a nornir task
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


def get_firmware():
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

    return devices


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
