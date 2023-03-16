#!/usr/bin/python
from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = r'''
---
module: create_secret_server_secret

short_description: Create a secret in Delineas Secret Server

version_added: "1.0.0"

description: |
    Create a secret in Delineas Secret Server using the Secret Servers API as a backend.
    Returns a secret variable that contains the secrets username and password.

options:
    secret_server_host:
        description: The hostname of your Secret Server instance
        required: true
        type: str
    secret_server_username_domain:
        description: The domain pertaining to your username. This is prepend to your username
        required: false
        type: str
    secret_server_username:
        description: The username of the user that will be used to contact the Secret Server API
        required: true
        type: str
    secret_server_password:
        description: The password of the user that will be used to contact the Secret Server API
        required: true
        type: str
    secret_folder:
        description: The name of the folder the secret will be placed in
        required: True
        type: str
    secret_template:
        description: The type of secret you want to create
        required: True
        type: str
    secret_name:
        description: The display name of the secret
        required: True
        type: str
    secret_items:
        description: Additional parameters for the chosen secret template
        required: False
        type: dict
    use_random_password:
        description: When true will generate a random password with requirements for secret_items.Password
        required: False
        type: bool
    random_password_alphabet:
        description: String containing all allowed characters for random password generation
        required: False
        type: str
    random_password_length:
        description: Number of characters the random password will contains
        required: False
        type: int
    random_password_uppercase_requirement:
        description: Minimum number of uppercase characters the random password will contain
        required: False
        type: int
    random_password_lowercase_requirement:
        description: Minimum number of lowercase characters the random password will contain
        required: False
        type: int
    random_password_digit_requirement:
        description: Minimum number of digit characters the random password will contain
        required: False
        type: int
    random_password_special_requirement:
        description: Minimum number of special characters the random password will contain
        required: False
        type: int
    sha512_encrypt_password:
        description: Output for password parameter will be sha512 encrypted for security purposes
        required: False
        type: bool
    secret_overwrite:
        description: Flag to enable overwriting of an existing secret
        required: False
        type: bool

author:
    - Zachary Plencner (@zachary-plencner)
'''

EXAMPLES = r'''
# Create a 'Windows Account' Secret
- name: Create a new secret
    create_windows_secret_server_secret:
      secret_server_host: 'https://contoso.secretservercloud.com'
      secret_server_username_domain: "contoso"
      secret_server_username: "john.doe"
      secret_server_password: "password123"
      secret_folder: "/My Secrets"
      secret_name: "My Workstation"
      secret_template: "Windows Account"
      secret_items:
        Machine: "DESKTOP-Q66XZA5"
        Username: "jdoe"
        Password: "password123"

# Create a 'Password' Secret
- name: Create Secret
    create_windows_secret_server_secret:
      secret_server_host: 'https://contoso.secretservercloud.com'
      secret_server_username_domain: "contoso"
      secret_server_username: "jane.doe"
      secret_server_password: "password123"
      secret_folder: "/My Secrets/Linux Secrets"
      secret_name: "database-1 secret"
      secret_template: "Password"
      secret_items:
        Username: "root"
        Password: "Q1am9a!aSl"
        Resource: "database-1"
        Notes: "Root login for database-1"
    sha512_encrypt_password: yes
    secret_overwrite: True

# Create a 'Active Directory Account" Secret with random password
- name: Create Secret
    create_windows_secret_server_secret:
      secret_server_host: 'https://contoso.secretservercloud.com'
      secret_server_username_domain: "contoso"
      secret_server_username: "jane.doe"
      secret_server_password: "password123"
      secret_folder: "/My Secrets/Active Directory Secrets/jdoe1"
      secret_name: "jdoe1 AD password"
      secret_template: "Active Directory Account"
      secret_items:
        Username: "jdoe1"
        Domain: "contoso"
        Notes: "My AD Secret"
    use_random_password: yes
    random_password_length: 12
    random_password_alphabet: 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyzy0123456789!@$%^&'
    random_password_uppercase_requirement: 1
    random_password_lowercase_requirement: 1
    random_password_digit_requirement: 1
    random_password_special_requirement: 1
    secret_overwrite: True
'''

RETURN = r'''
secret:
    description: The items contained in the secret
    type: str
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

    result['Result'] = machine

    # in the event of a successful module execution, you will want to
    # simple AnsibleModule.exit_json(), passing the key/value results
    module.exit_json(**result)


def main():
    run_module()


if __name__ == '__main__':
    main()
