#!/usr/bin/python
from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = r'''
---
module: modify_asset

short_description: Modify an Asset in Quest's K1000 CMDB

version_added: "2.4.0"

description: |
    Modify an Asset in Quest's K1000 CMDB using the K1000's API as a backend.
    Returns information about the targeted asset.

options:
    k1000_host:
        description: The hostname of K1000 instance
        required: true
        type: str
    k1000_username:
        description: The username of the user to connect to the K1000 API
        required: true
        type: str
    k1000_password:
        description: The password of the user to connect to the K1000 API
        required: true
        type: str
    k1000_totp_secret:
        description: The TOTP secret of the user to connect to the K1000 API
        required: true
        type: str
    k1000_org:
        description: The K1000 ORG to land in after login
        required: true
        type: str
    asset_name:
        description: What to name the new asset
        required: true
        type: str
    asset_type_id:
        description: The id of the asset type you want to create
        required: true
        type: int
    asset_fields:
        description: Free form dictionary of fields to add to the new asset
        required: true
        type: dict

author:
    - Zachary Plencner (@zachary-plencner)
'''

EXAMPLES = r'''
# Create a 'Windows Account' Secret
- name: Create KACE Asset
    zachary_plencner.k1000.modify_asset:
      k1000_host: "https://k1000.contoso.org"
      k1000_username: "John.Doe"
      k1000_password: "password123"
      k1000_totp_secret: "ABCDEFGHIJKLMNOPQRSTUVWXYZ123456"
      k1000_org: "Org1"
      asset_name: "My New Asset"
      asset_type_id: 8
      asset_fields:
        owner_id: "123"
        field_12345:
          id: "1234"
        location_id: "12345"
'''

RETURN = r'''
assets:
    description: Information about the asset(s)
    type: dict
    returned: always
    sample:
        asset:
            field_1: foo
            field_2: bar
            field_3: foo
            field_N: bar
'''

from ansible.module_utils.basic import AnsibleModule
import requests
import pyotp

# Transform a dictionary to index by specific key in each dict
def json_index_transform(dictionary, key):
    transformed_dictionary = {}
    for sub_dictionary in dictionary:
        transformed_dictionary[sub_dictionary[key]] = sub_dictionary

    return transformed_dictionary


# object for maintaining session to K1000
class LogOn:
    def __init__(self, k1000_host, k1000_username, k1000_password, k1000_totp_secret, k1000_org):
        self.k1000_host = k1000_host
        self.k1000_username = k1000_username
        self.k1000_password = k1000_password
        self.k1000_totp_secret = k1000_totp_secret
        self.k1000_org = k1000_org
        self.k1000_logon_uri = k1000_host + '/ams/shared/api/security/login'
        self.k1000_2FA_uri = k1000_host + '/ams/shared/api/security/verify_2factor'
        self.k1000_base_url = k1000_host + '/api/v1'
        self.k1000_grant_type = 'password'
        if None != k1000_totp_secret:
            k1000_2fa_secret = pyotp.TOTP(k1000_totp_secret)

            # Obtain Current 2FA Token
            k1000_2fa_token = k1000_2fa_secret.now()
            self.k1000_logon_2fa_data = dict(currentCode=k1000_2fa_token)

        # Create dictionaries with login data
        self.k1000_logon_data = dict(
            userName=k1000_username, password=k1000_password, organizationName=k1000_org)

        # Send POST to K1000 to retrieve authentication token.
        k1000_r = requests.post(self.k1000_logon_uri, json=self.k1000_logon_data)

        if k1000_r.status_code != 200:
            raise Exception("Login failed")

        # Create variable for managing authentication and populate it from initial request
        self.k1000_jar = k1000_r.cookies

        # Create mandatory header variable for interaction with the K1000 API
        self.k1000_headers = {'Content-Type': 'application/json', 'Accept': 'application/json',
                        'x-kace-authorization': k1000_r.headers['x-kace-authorization'], 'x-kace-api-version': '8.1'}

        if None != k1000_totp_secret:
            # Verify 2FA Token and Authorize Session
            k1000_r_2FA = requests.post(
                self.k1000_2FA_uri, headers=self.k1000_headers, cookies=self.k1000_jar, json=self.k1000_logon_2fa_data)

            if k1000_r_2FA.status_code != 200:
                raise Exception("Login failed")


# API get method
def get(k1000_server_logon, endpoint):
    k1000_server_endpoint = k1000_server_logon.k1000_base_url + endpoint

    r = requests.get(
        k1000_server_endpoint, headers=k1000_server_logon.k1000_headers, cookies=k1000_server_logon.k1000_jar)

    return r.json()


# API post method (with payload)
def post(k1000_server_logon, endpoint, payload):
    k1000_server_endpoint = k1000_server_logon.k1000_base_url + endpoint

    r = requests.post(
        k1000_server_endpoint, headers=k1000_server_logon.k1000_headers, cookies=k1000_server_logon.k1000_jar, json=payload)

    return r.json()


# API put method (with payload)
def put(k1000_server_logon, endpoint, payload):
    k1000_server_endpoint = k1000_server_logon.k1000_base_url + endpoint

    r = requests.put(
        k1000_server_endpoint, headers=k1000_server_logon.k1000_headers, cookies=k1000_server_logon.k1000_jar, json=payload)

    return r.json()


# API delete method
def delete(k1000_server_logon, endpoint):
    k1000_server_endpoint = k1000_server_logon.k1000_base_url + endpoint

    r = requests.delete(
        k1000_server_endpoint, headers=k1000_server_logon.k1000_headers, cookies=k1000_server_logon.k1000_jar)

    return r.json()

def compare_dicts(dict_a, dict_b):
    for key, value_a in dict_a.items():
        if key not in dict_b:
            return False

        value_b = dict_b[key]

        if isinstance(value_a, dict) and isinstance(value_b, dict):
            if not compare_dicts(value_a, value_b):
                return False
        elif str(value_a) != str(value_b):
            return False

    return True

def run_module():
    # define available arguments/parameters a user can pass to the module
    module_args = dict(
        k1000_host=dict(type='str', required=True),
        k1000_username=dict(type='str', no_log=True, required=True),
        k1000_password=dict(type='str', no_log=True, required=True),
        k1000_totp_secret=dict(type='str', no_log=True, required=False),
        k1000_org=dict(type='str', no_log=False, required=True),
        asset_name=dict(type='str', required=True),
        asset_type_id=dict(type='str', required=True),
        asset_fields=dict(type='dict', required=True),
    )

    # seed the result dict in the object
    result = dict(
        changed=False
    )

    # the AnsibleModule object will be our abstraction working with Ansible
    # this includes instantiation, a couple of common attr would be the
    # args/params passed to the execution, as well as if the module
    # supports check mode
    module = AnsibleModule(
        argument_spec=module_args,
        supports_check_mode=True
    )

    if None == module.params['k1000_totp_secret']:
        module.params['k1000_totp_secret'] = None

    # Create LogOn session object for rest of module
    k1000_logon = LogOn(module.params['k1000_host'],
                        module.params['k1000_username'],
                        module.params['k1000_password'],
                        module.params['k1000_totp_secret'],
                        module.params['k1000_org']
                        )

    asset = module.params['asset_fields']

    asset.update(name=module.params['asset_name'], asset_type_id=module.params['asset_type_id'])

    # get asset record
    endpoint = k1000_logon.k1000_host + '/api/asset/assets?filtering=name co ' + module.params['asset_name'] + ',asset_type_id eq ' + module.params['asset_type_id']
    r = requests.get(
        endpoint, headers=k1000_logon.k1000_headers, cookies=k1000_logon.k1000_jar)
    json_data = r.json()
    if len(json_data['Assets']) == 0:
        # create asset record
        endpoint = k1000_logon.k1000_host + '/api/asset/assets'
        requestbody = {"Assets": [asset]}
        r = requests.post(
            endpoint, headers=k1000_logon.k1000_headers, cookies=k1000_logon.k1000_jar, json=requestbody)
        json_data = r.json()
        asset_id = json_data['IDs'][0]
    else:
        # Determine if changes need to be made
        result['changed'] = not compare_dicts(asset, json_data['Assets'][0])

        # update asset
        if result['changed'] == True:
            requestbody = {"Assets": [asset]}
            k1000_endpoint = k1000_logon.k1000_host + '/api/asset/assets/' + str(json_data['Assets'][0]['id'])
            r = requests.put(k1000_endpoint, headers=k1000_logon.k1000_headers, cookies=k1000_logon.k1000_jar, json=requestbody)
            if r.status_code != 200:
                module.fail_json(msg='Could not update asset. Full response: ' + str(r.json()))

        asset_id = json_data['Assets'][0]['id']

    # Get detailed asset record
    endpoint = k1000_logon.k1000_host + '/api/asset/assets/' + str(asset_id)
    r = requests.get(
        endpoint, headers=k1000_logon.k1000_headers, cookies=k1000_logon.k1000_jar)
    json_data = r.json()
    assets = json_data

    result['asset'] = assets['Assets'][0]

    # in the event of a successful module execution, you will want to
    # simple AnsibleModule.exit_json(), passing the key/value results
    module.exit_json(**result)


def main():
    run_module()


if __name__ == '__main__':
    main()
