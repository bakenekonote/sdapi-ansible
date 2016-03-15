#!/usr/bin/python

# import some python modules that we'll use.  These are all
# available in Python's core

import json
import requests
import xml.etree.ElementTree as ET
import base64
import re
import logging
import time
import os
from jinja2 import Template

class Sdapi(object):

	def __init__(self, module):
		self.module = module
		
		# copy paramaters to self object
		self.action = module.params['action']
		self.junosspace_host = module.params['junosspace_host']
		self.junosspace_username = module.params['junosspace_username']
		self.junosspace_password = module.params['junosspace_password']
		self.device = module.params['device']
		self.change_request_id = module.params['change_request_id']
		self.action = module.params['action']
		self.publish = module.params['publish']
		self.update_devices = module.params['update_devices']
		self.source_addresses = module.params['source_addresses']
		self.source_zone = module.params['source_zone']
		self.destination_addresses = module.params['destination_addresses']
		self.destination_zone = module.params['destination_zone']
		self.services = module.params['services']

		# Mark if changes are made
		self.changed = False
		
		#REST Headers
		self.auth_header = { 'Authorization' : 'Basic ' + base64.b64encode(self.junosspace_username + ':' + self.junosspace_password) }
		self.address_content_type_header = { 'Content-Type' : 'application/vnd.juniper.sd.address-management.address+xml;version=1;charset=UTF-8' }
		self.publish_policy_content_type_header = { 'Content-Type' : 'application/vnd.juniper.sd.fwpolicy-management.publish+xml;version=1;charset=UTF-8' }
		self.modify_rules_content_type_header = { 'Content-Type' : 'application/vnd.juniper.sd.fwpolicy-management.modify-rules+xml;version=1;charset=UTF-8' }
		self.update_devices_content_type_header = { 'Content-Type' : 'application/vnd.juniper.sd.device-management.update-devices+xml;version=1;charset=UTF-8' }
		
		

		#REST POST Template (may put to another template file later)
		self.add_address_xml = Template("""<address>
	<name>sd-api-host-{{ address }}</name>
	<address-type>{{ type }}</address-type>
	<ip-address>{{ address }}</ip-address>
</address>""")
		self.publish_policy_xml = Template("""<publish>
	<policy-ids>
		<policy-id>{{ policy_id }}</policy-id>
	</policy-ids>
</publish>""")
		self.update_devices_xml = Template("""<update-devices>
	<sd-ids>
		<id>{{ device_id }}</id>
	</sd-ids>
	<service-types>
		<service-type>POLICY</service-type>
	</service-types>
	<update-options>
		<enable-policy-rematch-srx-only>boolean</enable-policy-rematch-srx-only>
	</update-options>
</update-devices>""")
		self.modify_rules_xml = Template("""<modify-rules>
	<edit-version>{{ policy_edit_ver }}</edit-version>
	<policy-id>{{ policy_id }}</policy-id>
	<added-rules>
		<added-rule>
			<name>{{ rule_name }}</name>
			<source-zones>
				<source-zone>
					<name>{{ src_zone }}</name>
					<zone-type>ZONE</zone-type>
				</source-zone>
			</source-zones>
			<source-addresses>{% for src_obj in src_objs %}
				<source-address>
					<id>{{ src_obj.id }}</id>
					<name>{{ src_obj.name }}</name>
					<address-type>{{ src_obj.type }}</address-type>
				</source-address>{% endfor %}
			</source-addresses>
			<source-excluded-address>false</source-excluded-address>
			<source-identities/>
			<destination-zones>
				<destination-zone>
					<name>{{ dst_zone }}</name>
					<zone-type>ZONE</zone-type>
				</destination-zone>
			</destination-zones>
			<destination-addresses>{% for dst_obj in dst_objs %}
				<destination-address>
					<id>{{ dst_obj.id }}</id>
					<name>{{ dst_obj.name }}</name>
					<address-type>{{ dst_obj.type }}</address-type>
				</destination-address>{% endfor %}
			</destination-addresses>
			<destination-excluded-address>false</destination-excluded-address>
			<services>{% for srv_obj in srv_objs %}
				<service>
					<id>{{ srv_obj.id }}</id>
					<name>{{ srv_obj.name }}</name>
				</service>{% endfor %}
			</services>
			<action>PERMIT</action>
			<vpn-tunnel-refs/>
			<application-signature-type>NONE</application-signature-type>
			<application-signatures/>
			<rule-profile>
				<profile-type>INHERITED</profile-type>
			</rule-profile>
			<ips-mode>NONE</ips-mode>
			<ips-enabled>false</ips-enabled>
			<scheduler/>
			<utm-policy/>
			<secintel-policy/>
			<custom-column/>
			<edit-version>0</edit-version>
			<definition-type>CUSTOM</definition-type>
			<rule-group-type>CUSTOM</rule-group-type>
			<rule-group-id>{{ device_rule_id }}</rule-group-id>
			<rule-type>RULE</rule-type>
			<policy-name>{{ device }}</policy-name>
			<enabled>true</enabled>
		</added-rule>
	</added-rules>
</modify-rules>""")
		
	def add_address(self, address):
		logging.debug("Address address object %s" % address)

		#input check
		if re.search('^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)/(?:3[0-2]|[012]?[0-9]?)$', address): 
			type = "NETWORK"
		elif re.search('^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$', address):
			type = "IPADDRESS"
		else:
			raise Exception('invalid IP address format ' + address)

		# Mark changed
		self.changed = True
		if self.module.check_mode:
			return

		# REST call to Security Directory to add address
		xml = self.add_address_xml.render(address=address, type=type)
		resp = requests.post('https://' + self.junosspace_host + '/api/juniper/sd/address-management/addresses',
								headers=dict(self.auth_header, **self.address_content_type_header),
								data=xml,
								verify=False
							)
		if resp.status_code != 200:
			raise Exception('POST address-management/addresses {}'.format(resp.status_code))
		root = ET.fromstring(resp.text)
		result = dict(name=root.find('name').text, id=root.find('id').text, type=root.find('address-type').text)
		return result

	def check_add_address(self, address):
		logging.debug("Getting address reference %s" % address)
		resp = requests.get('https://' + self.junosspace_host + '/api/juniper/sd/address-management/addresses', headers=self.auth_header, verify=False)
		if resp.status_code != 200:
			raise Exception('GET address-management/addresses {}'.format(resp.status_code))
		root = ET.fromstring(resp.text)
		node = root.find('./address[ip-address="' + address + '"]')

		#if address object exists
		if (node is not None):
			result = dict(name=node.find('./name').text, id=node.find('./id').text, type=node.find('./address-type').text)
		else:
			logging.info("Address %s not found!, adding it to SD" % address)
			result = self.add_address(address)
		return result
		
	def check_service(self, service):
		logging.debug("Getting service reference %s" % service)
		resp = requests.get('https://' + self.junosspace_host + '/api/juniper/sd/service-management/services?filter=(global eq \'' + service + '\')' , headers=self.auth_header, verify=False)
		if resp.status_code != 200:
			raise Exception('GET service-management/services {}'.format(resp.status_code))
		root = ET.fromstring(resp.text)
		node = root.find('./service[name="' + service + '"]')

		#if service object exists
		if (node is not None):
			result = dict(name=node.find('./name').text, id=node.find('./id').text)
			return result
		else:
			raise Exception('Service not found')
	
	def get_device(self, device):
		logging.debug("Getting device reference %s" % device)
		resp = requests.get('https://' + self.junosspace_host + '/api/juniper/sd/device-management/devices' , headers=self.auth_header, verify=False)
		if resp.status_code != 200:
			raise Exception('GET device-management/devices {}'.format(resp.status_code))
		root = ET.fromstring(resp.text)
		node = root.find('./device[name="'+ device +'"]')
		#if device object exists
		if (node is not None):
			result = dict(name=node.find('./name').text, id=node.find('./id').text, policy_name=node.find('./assigned-services/assigned-service/name').text)
			return result
		else:
			raise Exception('Device not found')

	def get_policy(self, policy):
		logging.debug("Getting policy reference %s" % policy)
		resp = requests.get('https://' + self.junosspace_host + '/api/juniper/sd/fwpolicy-management/firewall-policies?filter=(global eq \'' + policy + '\')'  , headers=self.auth_header, verify=False)
		if resp.status_code != 200:
			raise Exception('GET fwpolicy-management/firewall-policies {}'.format(resp.status_code))
		root = ET.fromstring(resp.text)
		node = root.find('./firewall-policy[type="DEVICE"]')
		#if device object exists
		if (node is not None):
			policy_id = node.find('./id').text
		else:
			raise Exception('Policy not found')
		
		
		#search policy edit version
		resp = requests.get('https://' + self.junosspace_host + '/api/juniper/sd/fwpolicy-management/firewall-policies/' + policy_id  , headers=self.auth_header, verify=False)
		root = ET.fromstring(resp.text)
		edit_version = root.find('./edit-version').text
		
		#search policy zone rule id
		resp = requests.get('https://' + self.junosspace_host + '/api/juniper/sd/fwpolicy-management/firewall-policies/' + policy_id + '/firewall-rules'  , headers=self.auth_header, verify=False)
		root = ET.fromstring(resp.text)
		zone_rule_id = root.find('./firewall-rule[rule-group-type="ZONE"]/id').text
		
		#search device rule id
		resp = requests.get('https://' + self.junosspace_host + '/api/juniper/sd/fwpolicy-management/firewall-rules/' + zone_rule_id + '/members'  , headers=self.auth_header, verify=False)
		root = ET.fromstring(resp.text)
		device_rule_id = root.find('./firewall-rule[rule-group-type="DEVICE"]/id').text
		
		return dict(policy_id=policy_id, edit_version=edit_version, zone_rule_id=zone_rule_id, device_rule_id=device_rule_id )
	
	def publish_policy(self, policy_id):
		xml = self.publish_policy_xml.render(policy_id = policy_id)
		resp = requests.post('https://' + self.junosspace_host + '/api/juniper/sd/fwpolicy-management/publish',
								headers=dict(self.auth_header, **self.publish_policy_content_type_header),
								data=xml,
								verify=False,
							)
		if resp.status_code != 202:
			raise Exception('Publish Policy Failure {}'.format(resp.status_code))
		task_id = ET.fromstring(resp.text).find('id').text;
		complete = False
		while (not complete) :
			time.sleep (1);
			resp = requests.get('https://' + self.junosspace_host + '/api/space/job-management/jobs/' + task_id,
							headers=self.auth_header,
							verify=False,
						)
			logging.debug("Publish Policy Job Result: %s" % resp.text)
			if ET.fromstring(resp.text).find('job-status').text != "UNDETERMINED":
				complete = True

	def update_device(self, device_id):
		xml = self.update_devices_xml.render(device_id = device_id)
		resp = requests.post('https://' + self.junosspace_host + '/api/juniper/sd/device-management/update-devices',
								headers=dict(self.auth_header, **self.update_devices_content_type_header),
								data=xml,
								verify=False,
							)
		if resp.status_code != 202:
			raise Exception('Update Device {}'.format(resp.status_code))
		task_id = ET.fromstring(resp.text).find('id').text;
		complete = False
		while (not complete) :
			time.sleep (1);
			resp = requests.get('https://' + self.junosspace_host + '/api/space/job-management/jobs/' + task_id,
							headers=self.auth_header,
							verify=False,
						)
			logging.debug("Update Device Job Result: %s" % resp.text)
			if ET.fromstring(resp.text).find('job-status').text != "UNDETERMINED":
				complete = True
	
	def lock_policy(self, policy_id):
		# REST call to acquire lock
		xml = ""
		resp = requests.post('https://' + self.junosspace_host + '/api/juniper/sd/fwpolicy-management/firewall-policies/' + policy_id + '/lock',
								headers=self.auth_header,
								data=xml,
								verify=False
							)
		if resp.status_code != 200:
			raise Exception('Policy Lock Failure {}'.format(resp.status_code))
		if re.search('Unable to acquire lock', resp.text):
			raise Exception('Policy Lock Failure {}'.format(resp.status_code))
		return resp.cookies
			
	def unlock_policy(self, policy_id, cookies):
		# REST call to release lock
		xml = ""
		resp = requests.post('https://' + self.junosspace_host + '/api/juniper/sd/fwpolicy-management/firewall-policies/' + policy_id + '/unlock',
								headers=self.auth_header,
								data=xml,
								verify=False,
								cookies=cookies
							)
		if resp.status_code != 200:
			raise Exception('Policy Unlock Failure {}'.format(resp.status_code))
			
	def add_rule(self):
		# Get Object Refeneces
		device_obj = self.get_device(self.device)

		# Get Source Address References, Add it if not found
		src_objs = []
		if isinstance(self.source_addresses, list):
                  for addr in self.source_addresses:
                    src_objs.append(self.check_add_address(addr))
		else :
                  src_objs.append(self.check_add_address(self.source_addresses))

		# Get Destination Address References, Add it if not found
		dst_objs = []
		if isinstance(self.destination_addresses, list):
                  for addr in self.destination_addresses:
                    dst_objs.append(self.check_add_address(addr))
		else :
                  dst_objs.append(self.check_add_address(self.destination_addresses))
               
		# Get Services References
		srv_objs = []
		if isinstance(self.services, list):
                  for service in self.services:
                    srv_objs.append(self.check_service(service))
		else :
		    srv_objs.append(self.check_service(self.services))
		
		policy_obj = self.get_policy(device_obj['policy_name'])
		logging.debug("policy_obj %s" % policy_obj)

		# check if rules already exist
		resp = requests.get('https://' + self.junosspace_host + '/api/juniper/sd/fwpolicy-management/firewall-rules/' + policy_obj['device_rule_id'] + '/members' , headers=self.auth_header, verify=False)
		if resp.status_code != 200:
			raise Exception('GET fwpolicy-management/firewall-rules/ {}'.format(resp.status_code))
		root = ET.fromstring(resp.text)
		node = root.find('./firewall-rule[name="'+ self.change_request_id + '"]')
		#if rules object exists
		if (node is not None):
			logging.warning("Firewall rules for change request %s already existed" % self.change_request_id);
		else :
			# add policy rules

			# Mark changed
			self.changed = True
			if self.module.check_mode:
				return

			# Acquiring Lock
			logging.info("Acquiring lock for policy %s" % device_obj['policy_name'])
			cookies = self.lock_policy(policy_obj['policy_id'])

			# Update Policy
			xml = self.modify_rules_xml.render( rule_name   = self.change_request_id,
													src_zone    = self.source_zone,
													src_objs    = src_objs,
													dst_zone    = self.destination_zone,
													dst_objs    = dst_objs,
													srv_objs    = srv_objs,
													policy_name = device_obj['policy_name'],
													device_rule_id = policy_obj['device_rule_id'],
													policy_id = policy_obj['policy_id'],
													policy_edit_ver = policy_obj['edit_version'])
			logging.debug("Dumping policy xml %s" % xml)
			logging.info("Modifing policy %s" % device_obj['policy_name'])
			resp = requests.post('https://' + self.junosspace_host + '/api/juniper/sd/fwpolicy-management/modify-rules',
									headers=dict(self.auth_header, **self.modify_rules_content_type_header),
									data=xml,
									verify=False,
									cookies=cookies
								)
			if resp.status_code != 204:
				print resp.text
				raise Exception('Modify Policy Failure {}'.format(resp.status_code))

			# Releasing Lock
			logging.info("Releasing lock for policy %s" % device_obj['policy_name'])
			self.unlock_policy(policy_obj['policy_id'],cookies)
		
		# Publish Policy
		if self.publish:
			logging.info("Publishing policy %s" % device_obj['policy_name'])
			self.publish_policy(policy_obj['policy_id'])
		
		# Update Device
		if self.update_devices:
			logging.info("Updating Device %s" % device_obj['id'])
			self.update_device(device_obj['id'])

	def if_changed(self):
		return self.changed
# ===========================================

def main():
	logging.basicConfig(filename="/tmp/sdapi.log",level=logging.DEBUG)
	module = AnsibleModule(
		argument_spec = dict(
			junosspace_host = dict(required=True),
			junosspace_username = dict(required=True),
			junosspace_password = dict(required=True),
			change_request_id = dict(required=True),
			device = dict(required=True),
			action = dict(default='add', choices=['add', 'del']),
			publish = dict(default=True, type='bool'),
			update_devices = dict(default=True, type='bool'),
			source_addresses = dict(required=True),
			source_zone = dict(required=True),
			destination_addresses = dict(required=True),
			destination_zone = dict(required=True),
			services = dict(required=True),
		),
		supports_check_mode = True
	)
	if module.check_mode:
	# Check if any changes would be made but don't actually make those changes
		module.exit_json(changed=True)
	
	sdapi = Sdapi(module)
	# ignore any arguments without an equals in it

	if sdapi.action == "add":
		sdapi.add_rule()
		module.exit_json(changed=sdapi.if_changed())

	elif sdapi.action == "del":
	   rc = 1
	   module.fail_json(msg="not yet implemented")

# import module snippets
from ansible.module_utils.basic import *
if __name__ == '__main__':
	main()
