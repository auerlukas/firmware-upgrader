import json
import requests

api_token = '0123456789abcdef0123456789abcdef01234567'
api_url_base = 'http://0.0.0.0:32769/api/'

headers = {'Content-Type': 'application/json',
           'Authorization': 'Token {t}'.format(t=api_token)}


def get_sites():
    api_url = f'{api_url_base}dcim/sites'
    response = requests.get(api_url, headers=headers)

    if response.status_code == 200:
        return json.loads(response.content.decode('utf-8'))
    else:
        return None


def add_ip_address(ip_address, prefix_length):
    print('ntbx.add_ip_address()')
    api_url = f'{api_url_base}ipam/ip-addresses'
    payload = {'address': ip_address + '/' + prefix_length}
    response = requests.post(api_url, headers=headers, data=payload)

    if response.status_code == 200:
        return 'IP address {ip}/{prefix} added successfully.'.format(ip=ip_address, prefix=prefix_length)
    else:
        return 'an error occurred!'
