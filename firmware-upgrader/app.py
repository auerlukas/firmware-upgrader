import json
import logging
import re
import sys
import time
import urllib3
import yaml

# import openVulnQuery
# from openVulnQuery.query_client import OpenVulnQueryClient
# from openVulnQuery.advisory import AdvisoryIOS
from openVulnQuery._library.query_client import OpenVulnQueryClient
from openVulnQuery._library.advisory import AdvisoryIOS
from typing import List

from flask import Flask
from flask import render_template
from flask import request
from nornir.core import InitNornir
from nornir.plugins.tasks import networking
from nornir.plugins.tasks.networking import napalm_get
from nornir.plugins.functions.text import print_result
from redis import Redis
from rq import Queue


def reload_switch(self):
    for i in range(10):
        message = 'switch is rebooting: {i}%'.format(i=i*10)
        self.update_state(state='PROGRESS',
                          meta={'status': message})
        time.sleep(1)
    return {'current': 100, 'total': 100, 'status': 'Task completed!', 'result': 100}
    pass


def find_vulnerabilities(os: str = '', version: str = '') -> List[AdvisoryIOS]:
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

    query_client: OpenVulnQueryClient = OpenVulnQueryClient(
        client_id=credentials['CLIENT_ID'],
        client_secret=credentials['CLIENT_SECRET'])

    if os == 'ios':
        advisories: List[AdvisoryIOS] = query_client.get_by_ios('', version)
    elif os == 'ios-xe':
        advisories: List[AdvisoryIOS] = query_client.get_by_ios_xe('', version)
    return advisories


def get_sites() -> list:
    """
    reads the devices.yaml in the inventory directory and creates a distinct list of sites
    :return: returns a list of all sites
    """
    try:
        stream = open('inventory/devices.yaml')
    except FileNotFoundError as e:
        print('inventory file could not be found!\n{e}'.format(e=e), file=sys.stderr)
        sys.exit(1)

    devices = yaml.load(stream)

    sites = []
    for host, host_details in devices.items():
        if host_details['site'] not in sites:
            sites.append(host_details['site'])

    return sites


def get_devices() -> dict:
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
