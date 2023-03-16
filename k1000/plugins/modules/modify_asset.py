#!/usr/bin/python
from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = r'''
---
module: modify_asset

short_description: Modify an Asset in Quest's K1000 CMDB

version_added: "1.0.0"

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
    k1000_org: The K1000 ORG to land in after login
        description:
        required: true
        type: str
    machine_name: The name of the machine asset to modify
        description:
        required: true
        type: str
    owner_name: The fullname of the owner to assign to the targeted asset
        description:
        required: true
        type: str
    service_name:
        description: The name of the service to assign to the targeted asset
        required: true
        type: str

author:
    - Zachary Plencner (@zachary-plencner)
'''

EXAMPLES = r'''
# Create a 'Windows Account' Secret
- name: K1000 API
    zachary_plencner.k1000.modify_asset:
      k1000_host: "https://k1000.contoso.com"
      k1000_username: "k1000_admin"
      k1000_password: "password123"
      k1000_totp_secret: "ABCDEFGHIJKLMNOPQRSTUVWXYZ123456"
      k1000_org: "Workstations"
      machine_name: "server1"
      owner_name: "John Doe"
      service_name: "General Servers"
'''

RETURN = r'''
Machine:
    description: Information about the machine asset
    type: dict
    returned: always
    secret: {
        item1: "itemValue1",
        item2: "itemValue2",
        item3: "itemValue3",
        itemN: "itemValueN"
    }
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
        k1000_2fa_secret = pyotp.TOTP(k1000_totp_secret)

        # Obtain Current 2FA Token
        k1000_2fa_token = k1000_2fa_secret.now()

        # Create dictionaries with login data
        self.k1000_logon_data = dict(
            userName=k1000_username, password=k1000_password, organizationName=k1000_org)
        self.k1000_logon_2fa_data = dict(currentCode=k1000_2fa_token)

        # Send POST to K1000 to retrieve authentication token.
        k1000_r = requests.post(self.k1000_logon_uri, json=self.k1000_logon_data)

        if k1000_r.status_code != 200:
            raise Exception("Login failed")

        # Create variable for managing authentication and populate it from initial request
        self.k1000_jar = k1000_r.cookies

        # Create mandatory header variable for interaction with the K1000 API
        self.k1000_headers = {'Content-Type': 'application/json', 'Accept': 'application/json',
                        'x-kace-authorization': k1000_r.headers['x-kace-authorization'], 'x-kace-api-version': '8.1'}

        # Verify 2FA Token and Authorize Session
        k1000_r_2FA = requests.post(
            self.k1000_2FA_uri, headers=self.k1000_headers, cookies=self.k1000_jar, json=self.k1000_logon_2fa_data)

        if k1000_r_2FA.status_code != 200:
            raise Exception("Login failed")


# API get method
def get(secret_server_logon, endpoint):
    secret_server_endpoint = secret_server_logon.secret_server_base_url + endpoint

    r = requests.get(
        secret_server_endpoint, headers=secret_server_logon.secret_server_headers, cookies=secret_server_logon.secret_server_jar)

    return r.json()


# API post method (with payload)
def post(secret_server_logon, endpoint, payload):
    secret_server_endpoint = secret_server_logon.secret_server_base_url + endpoint

    r = requests.post(
        secret_server_endpoint, headers=secret_server_logon.secret_server_headers, cookies=secret_server_logon.secret_server_jar, json=payload)

    return r.json()


# API put method (with payload)
def put(secret_server_logon, endpoint, payload):
    secret_server_endpoint = secret_server_logon.secret_server_base_url + endpoint

    r = requests.put(
        secret_server_endpoint, headers=secret_server_logon.secret_server_headers, cookies=secret_server_logon.secret_server_jar, json=payload)

    return r.json()


# API delete method
def delete(secret_server_logon, endpoint):
    secret_server_endpoint = secret_server_logon.secret_server_base_url + endpoint

    r = requests.delete(
        secret_server_endpoint, headers=secret_server_logon.secret_server_headers, cookies=secret_server_logon.secret_server_jar)

    return r.json()


def run_module():
    # define available arguments/parameters a user can pass to the module
    module_args = dict(
        k1000_host=dict(type='str', required=True),
        k1000_username=dict(type='str', no_log=True, required=True),
        k1000_password=dict(type='str', no_log=True, required=True),
        k1000_totp_secret=dict(type='str', no_log=True, required=True),
        k1000_org=dict(type='str', no_log=False, required=True),
        machine_name=dict(type='str', no_log=False, required=True),
        owner_name=dict(type='str', no_log=False, required=True),
        service_name=dict(type='str', no_log=False, required=True)
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

    # Create LogOn session object for rest of module
    k1000_logon = LogOn(module.params['k1000_host'],
                                module.params['k1000_username'],
                                module.params['k1000_password'],
                                module.params['k1000_totp_secret'],
                                module.params['k1000_org']
                                )
                                
    # get user entry
    endpoint = k1000_logon.k1000_host + '/api/users/users?filtering=full_name eq ' + module.params['owner_name']
    r = requests.get(
        endpoint, headers=k1000_logon.k1000_headers, cookies=k1000_logon.k1000_jar)
    json_data = r.json()
    if len(json_data['Users']) == 0:
         module.fail_json(msg='No user with name ' + module.params['owner_name'])
    user = json_data['Users'][0]

    # get service entry
    endpoint = k1000_logon.k1000_host + '/api/asset/assets?filtering=asset_type_id eq 8,name eq ' + module.params['service_name']
    r = requests.get(
        endpoint, headers=k1000_logon.k1000_headers, cookies=k1000_logon.k1000_jar)
    json_data = r.json()
    if len(json_data['Assets']) == 0:
         module.fail_json(msg='No asset with name ' + module.params['service_name'])
    service = json_data['Assets'][0]

    # get machine entry
    endpoint = k1000_logon.k1000_host + '/api/asset/assets?filtering=asset_type_id eq 5,name eq ' + module.params['machine_name']
    r = requests.get(
        endpoint, headers=k1000_logon.k1000_headers, cookies=k1000_logon.k1000_jar)
    json_data = r.json()
    if len(json_data['Assets']) == 0:
         module.fail_json(msg='No machine with name ' + module.params['machine_name'])
    machine = json_data['Assets'][0]

    if machine['field_10067']['id'] != service['id']:
        machine['field_10067']['id'] = service['id']
        result['changed'] = True
    if machine['field_10067']['asset_type_id'] != service['asset_type_id']:
        machine['field_10067']['asset_type_id'] = service['asset_type_id']
        result['changed'] = True
    if machine['field_10067']['name'] != service['name']:
        machine['field_10067']['name'] = service['name']
        result['changed'] = True
    if machine['field_10067']['owner_id'] != service['owner_id']:
        machine['field_10067']['owner_id'] = service['owner_id']
        result['changed'] = True
    if machine['field_10067']['asset_class_id'] != service['asset_class_id']:
        machine['field_10067']['asset_class_id'] = service['asset_class_id']
        result['changed'] = True
    if machine['field_10067']['asset_status_id'] != service['asset_status_id']:
        machine['field_10067']['asset_status_id'] = service['asset_status_id']
        result['changed'] = True
    if machine['owner_id'] != user['id']:
        machine['owner_id'] = user['id']
        result['changed'] = True

    # update asset's assigned owner and service
    if result['changed'] == True:
        requestbody = {"Assets": [machine]}
        k1000_endpoint = k1000_logon.k1000_host + '/api/asset/assets/' + str(machine['id'])
        r = requests.put(k1000_endpoint, headers=k1000_logon.k1000_headers, cookies=k1000_logon.k1000_jar, json=requestbody)
        
        endpoint = k1000_logon.k1000_host + '/api/asset/assets?filtering=asset_type_id eq 5,name eq ' + module.params['machine_name']
        r = requests.get(
            endpoint, headers=k1000_logon.k1000_headers, cookies=k1000_logon.k1000_jar)
        json_data = r.json()
        machine = json_data['Assets'][0]

    result['Machine'] = machine

    # in the event of a successful module execution, you will want to
    # simple AnsibleModule.exit_json(), passing the key/value results
    module.exit_json(**result)


def main():
    run_module()


if __name__ == '__main__':
    main()
