#OpenVPN Dynamic Inventory
#Pieced together by Justin Mason

#Generic statement to ease migration to future versions of Python that introduce incompatible changes to the language. It allows use of the new features on a per-module basis before the release in which the feature becomes standard.
from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = r'''
    name: openvpn_dynamic_inventory
    plugin_type: inventory
    author: Justin Mason
    short_description: Builds OpenVPN Inventory
    description: Builds OpenVPN Inventory
    options:
        plugin:
            description: Plugin Name
            required: true
            choices: ['openvpn_dynamic_inventory']
        username:
            description: Username used for SCP to retrieve status files on OpenVPN Server. This user will need permission and should typically match ansible_user.
            required: true
        private_key:
            description: Location of private key that matches the authorized_keys for the username.
            required: false
        server_inventory:
            description: Should contain a list of the server FQDN's
            required: true
        gateway_inventory:
            description: Should contain a dictionary of the gateway short hostname and ip as a key:value pair. Optional.
            required: false
        manager_inventory:
            description: Should contain a list of the manager FQDN's
            required: false
    requirements:
        - paramiko
        - scp
'''
#Ansible
from ansible.plugins.inventory import BaseInventoryPlugin
from ansible.errors import AnsibleError, AnsibleParserError

#Additional Imports for OpenVPN specific methods
import csv
import os
import re
from paramiko import SSHClient
from paramiko import WarningPolicy
from scp import SCPClient

#See https://github.com/ansible/ansible/blob/stable-2.10/lib/ansible/inventory/data.py
class InventoryModule(BaseInventoryPlugin):
    NAME = 'openvpn_dynamic_inventory'

    #Verify inventory file type
    def verify_file(self, path):
        valid = False
        if super(InventoryModule, self).verify_file(path):
        #Base class verifies that file exists and is readable by current user
            if path.endswith(('.yaml', '.yml',)):
                valid = True
        return valid

    #Use local methods to build dynamic inventory
    def parse(self, inventory, loader, path, cache):
        #Call base method to ensure properties are available for use with other helper methods
        super(InventoryModule, self).parse(inventory, loader, path, cache)
        #Parse 'common format' inventory sources and update any options declared in DOCUMENTATION as needed
        config = self._read_config_data(path)
        try:
            # Load the options from the YAML file
            self.plugin = self.get_option('plugin')
            self.username = self.get_option('username')
            self.private_key = self.get_option('private_key')
            self.server_inventory = self.get_option('server_inventory')
            if self.get_option('gateway_inventory'):
                self.gateway_inventory = self.get_option('gateway_inventory')
            if self.get_option('manager_inventory'):
                self.manager_inventory = self.get_option('manager_inventory')  
        except Exception as e:
            raise AnsibleParserError('Required option not set: {}'.format(e))
        #Get OpenVPN Inventory, if there is a problem still build the rest of the inventory.     
        try:
            self.openvpn_inventory = self._pull_openvpn_information(username = self.username, private_key = self.private_key, server_inventory = self.server_inventory)     
        except Exception as e:
            print("\nCollector Inventory Error: " + str(e) + "\n")
            self.openvpn_inventory = {}
        #Build Groups
        groups = []
        #Regular Expressions for extracting group names from hostname
        regex = re.compile(r'-collector-\d+')
        #Parse hostnames for unique groups
        for hostname in self.openvpn_inventory:
            if (re.sub(regex, '', hostname.rstrip()) + "_collectors") not in groups:
                groups.append(re.sub(regex, '', hostname.rstrip()) + "_collectors")
        #Add the groups to the ansible inventory
        for group in groups:
            self.inventory.add_group(group)
        #Add hosts to the inventory
        for hostname,data in self.openvpn_inventory.items():
            self.inventory.add_host(host=hostname, group = (re.sub(regex, '', hostname.rstrip()) + "_collectors"))
            #Standard Variable
            self.inventory.set_variable(hostname, 'ansible_host', data['Virtual Address'])
            #Additional Variables
            self.inventory.set_variable(hostname, 'real_address', data['Real Address'])
            self.inventory.set_variable(hostname, 'client_id', data['Client ID'])
            self.inventory.set_variable(hostname, 'peer_id', data['Peer ID'])
        #Servers
        self.inventory.add_group("mdn_rallypoints")
        for hostname in self.server_inventory:
            self.inventory.add_host(host=hostname, group = "mdn_rallypoints")
        #Gateways
        if self.get_option('gateway_inventory'):
            self.inventory.add_group("mdn_gateways")
            for hostname,ip in self.gateway_inventory.items():
                self.inventory.add_host(host=hostname, group = "mdn_gateways")
                self.inventory.set_variable(hostname, 'ansible_host', ip)
        #Managers
        if self.get_option('manager_inventory'):
            self.inventory.add_group("mdn_managers")
            for hostname in self.manager_inventory:
                self.inventory.add_host(host=hostname, group = "mdn_managers")

    #OpenVPN Specific Methods
    def _create_ssh_client(self, server,username,key_filename):
        #Create client object
        client = SSHClient()
        #Read local known_hosts file
        client.load_system_host_keys()
        #Warn user if the host key is unknown
        client.set_missing_host_key_policy(WarningPolicy())
        #Connect to target
        client.connect(hostname = server, username = username, key_filename = key_filename)
        return client

    def _pull_openvpn_information(self, username,private_key,server_inventory):
        #Create inventory files directory if it does not exist, if it does make sure it's empty
        if not os.path.isdir("/tmp/openvpn/"):
            os.mkdir("/tmp/openvpn/")
        else:
            for file in os.listdir("/tmp/openvpn/"):
                os.remove("/tmp/openvpn/" + file)
        #Retrieve inventory files from each server
        for server in server_inventory:
            ssh = self._create_ssh_client(server = server, username = username, key_filename = private_key)
            scp = SCPClient(ssh.get_transport(), sanitize=lambda x: x)
            scp.get(remote_path = "/var/log/openvpn/*.status", local_path = "/tmp/openvpn")
            ssh.close()
        #Read files into memory
        #Create object and add first entry that csv.DictReader will use as the field names
        openvpn_csv = ["Common Name,Real Address,Virtual Address,Virtual IPv6 Address,Bytes Received,Bytes Sent,Connected Since,Connected Since (time_t),Username,Client ID,Peer ID"]
        #Regular expression to match line with the information we want
        regex = re.compile(r'^CLIENT_LIST,')
        #Read each file and add that information to openvpn_csv
        for file in os.listdir("/tmp/openvpn/"):
            with open("/tmp/openvpn/" + file) as fp:
                for line in fp:
                    if regex.search(line.rstrip()):
                        openvpn_csv.append(re.sub(regex, '', line.rstrip()))
        #Create a dictionary from the csv
        openvpn_dictionary = csv.DictReader(openvpn_csv)        
        #Convert to a dictionary with keys based on hostnames, only match collectors
        regex2 = re.compile(r'-collector-\d+')
        openvpn_inventory = {}
        for rows in openvpn_dictionary:
            if regex2.search(rows['Common Name']):
                hostname = rows['Common Name']
                #Set the inventory_data keys as the hostname, value is the dictionary in the current iteration of inventory_dictreader
                openvpn_inventory[hostname] = rows
        return openvpn_inventory