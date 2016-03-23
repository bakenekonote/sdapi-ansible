#!/usr/bin/python

# import some python modules that we'll use.  These are all
# available in Python's core

DOCUMENTATION = '''
---
module: sdapi
short_description: Ansible Module for Juniper Networks Junosspace Security Director policy management
description:
	- M(SDAPI) is a ansible module to manipulate Juniper Networks Junosspace Security Director firewall policies
	- Key Features includes 
	- firewall rules management (add/delete rules)
	- auto device selection and zone discovery by route checking
	- change control workflow
	- commit and apply changes to firewall devices
version_added: "1.0"
author: "Tony Chan, tonychan@juniper.net"
notes:
	- current version is tested against Junosspace Security Director 15.1R2 with Ansible 1.9
requirements:
	- Junospace Security Director 15.1R2
	- SRX/vSRX firewall(s)
	- jinja2 python module
	- requests python module
options:
	junosspace_host:
		description:
			- Junosspace host (IP/FQDN)
		required: true
		default: null
		choices: []
		aliases: []
		version_added: 1.0
	junosspace_username:
		description: 
			- Junosspace API username
		required: true
		default: null
		choices: []
		aliases: []
		version_added: 1.0
	junosspace_password:
		description:
			- Junosspace API password
		required: true
		default: null
		choices: []
		aliases: []
		version_added: 1.0
	change_request_id:
		description:
			- Change Request ID (should be unique among policy change). This will be used as the rule name in the device policy
		required: true
		default: null
		choices: []
		aliases: []
		version_added: 1.0
	device:
		description:
			- Firewall device name. Automatic device selection will be disabled if argument is supplied
		required: false
		default: null
		choices: []
		aliases: []
		version_added: 1.0
	action:
		description:
			- Action to perform (add / delete) policy rules
		required = true
		default: null
		choices: ['add', 'del']
		aliases: []
		version_added: 1.0
	publish:
		description:
			- Publish the updated policy (when change_control_workflow is disabled)
		required = false
		default: true
		choices: [true, false]
		aliases: []
		version_added: 1.0
	change_control_workflow:
		description:
			- use change control workflow in Security Directory. Must set to true if enabled in SD
		required: false
		default: false
		choices: [true, false]
		aliases: []
		version_added: 1.0
	update_devices:
		description:
			- Push policy changes to device (when change_control_workflow is disabled)
		required = false
		default: true
		choices: [true, false]
		aliases: []
		version_added: 1.0
	source_addresses:
                description:
                        - list of source addresses(ip or cidr). Will create address object in Security Director if object doesn't exists.
			- e.g. [ '192.168.1.1', '172.16.1.0/24' ]
                required = true
                default: null
                choices: []
                aliases: []
                version_added: 1.0
	source_zone:
		description:
			- source address zone, required if device is specified in argument
			- e.g. zone_a
                required = false
                default: null
                choices: []
                aliases: []
                version_added: 1.0
	destination_addresses:
                description:
                        - list of destination addresses(ip or cidr). Will create address object in Security Director if object doesn't exists.
			- e.g. [ '192.168.2.2', '172.16.2.0/24' ]
                required = true
                default: null
                choices: []
                aliases: []
                version_added: 1.0
	destination_zone:
		description:
			- destination address zone, required if device is specified in argument
			- e.g. zone_b
                required = false
                default: null
                choices: []
                aliases: []
                version_added: 1.0
	services:
                description:
                        - list of services to be allowed. Must be predefined in Security Director.
			- e.g. [ 'http', 'ftp', 'dns-udp' ]
                required = true
                default: null
                choices: []
                aliases: []
                version_added: 1.0
'''

EXAMPLE = '''
- action: SDAPI junosspace_host=space.example.com --extra-vars '{"junosspace_user":"super","junosspace_password":"juniper123","change_request_id":"cr1234","device":"labsrx","action":"add","source_address":["10.1.1.1","10.2.1.0/24"],"source_zone":"zone_a","destination_addresses":["8.8.8.8"],"destination_zone":"internet","services":"icmp-ping"}'
'''

RETURN = '''

'''

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
		self.change_control_workflow = module.params['change_control_workflow']
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
		self.create_cr_content_type_header = { 'Content-Type' : 'application/vnd.juniper.sd.change-request-management.change-request+xml;version=1;charset=UTF-8' }
		self.approve_cr_content_type_header = { 'Content-Type' : 'application/vnd.juniper.sd.change-request-management.approve-change-requests-request+xml;version=1;charset=UTF-8' }
		self.deploy_cr_content_type_header = { 'Content-Type' : 'application/vnd.juniper.sd.change-request-management.deploy-request+xml;version=1;charset=UTF-8' }
		self.exec_scripts_content_type_header = { 'Content-Type' : 'application/vnd.net.juniper.space.script-management.exec-scripts+xml;version=2;charset=UTF-8' }

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
		self.delete_rules_xml = Template("""<modify-rules>
<edit-version>{{ policy_edit_ver }}</edit-version>
	<policy-id>{{ policy_id }}</policy-id>
	<deleted-rules>{% for rule_id in rules %}
		<deleted-rule>{{ rule_id }}</deleted-rule>{% endfor %}
	</deleted-rules>
</modify-rules>""")
		self.modify_rules_xml = Template("""<modify-rules>
	<edit-version>{{ policy_edit_ver }}</edit-version>
	<policy-id>{{ policy_id }}</policy-id>
	<added-rules>{% for src in src_zone %}{%for dst in dst_zone %}
		<added-rule>
			<name>{{ rule_name }}</name>
			<source-zones>
				<source-zone>
					<name>{{ src }}</name>
					<zone-type>ZONE</zone-type>
				</source-zone>
			</source-zones>
			<source-addresses>{% for src_obj in src_zone[src] %}
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
					<name>{{ dst }}</name>
					<zone-type>ZONE</zone-type>
				</destination-zone>
			</destination-zones>
			<destination-addresses>{% for dst_obj in dst_zone[dst] %}
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
		</added-rule>{% endfor %}{% endfor %}
	</added-rules>
</modify-rules>""")
		self.create_cr_xml = Template("""<change-request>
	<priority>{{ priority }}</priority>
	<description>{{ description }}</description>
	<policy-id>{{ policy_id }}</policy-id>
	<approval-due-date>{{ due_date }}</approval-due-date>
	<name>{{ cr_name }}</name>
	<ticket-no/>
	<service-type>POLICY</service-type>
	<approval-status>PENDING</approval-status>
</change-request>""")
		self.approve_cr_xml = Template("""<approve-change-requests-request>
	<id-list>
	<id-list>{{ cr_id }}</id-list>
	</id-list>
	<comments>{{ comments }}</comments>
</approve-change-requests-request>""")
		self.deploy_cr_xml = Template("""<deploy-request>
	<schedule-time>0</schedule-time>
</deploy-request>""")
		self.exec_scripts_xml = Template("""<exec-scripts>
   <scriptMgmt>
         <script href='/api/space/script-management/scripts/{{ script_id }}' />
         <device href='/api/space/device-management/devices/{{ device_id }}' />
         <scriptVersionSelected>1.0</scriptVersionSelected>
         <scriptParams>
           <scriptParam>
                 <paramName>address-list</paramName>
                 <paramValue>{{ address_list }}</paramValue>
           </scriptParam>
           <scriptParam>
                 <paramName>default-route</paramName>
                 <paramValue>{{ default_route }}</paramValue>
           </scriptParam>
         </scriptParams>
   </scriptMgmt>
</exec-scripts>""")

	def wait_for_job_complete(self, task_id):
		while True :
			job_status = self.url('get', '/api/space/job-management/jobs/' + task_id).find('job-status').text
			if job_status != "UNDETERMINED": break
			time.sleep(1)
		return job_status
	
	def url(self, method, url, headers={}, verify=False, get_cookie=False, **kargs):
		headers = dict(self.auth_header, **headers)
		url = 'https://' + self.junosspace_host + url
		resp = getattr(requests, method)(url, headers=headers, verify=verify, **kargs)
		
		if not str(resp.status_code).startswith('2'):
			logging.debug('Dump API result: %s', resp.text)
			raise Exception('%s %s: %s' % (method.upper(), url, resp.status_code))
		
		if not get_cookie and resp.text:
			return ET.fromstring(resp.text)
		else:
			return resp.cookies
		
	def add_address(self, address):
		logging.debug('Adding address address object %s' % address)

		#input check
		if re.search('^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)/(?:3[0-2]|[012]?[0-9]?)$', address): 
			type = "NETWORK"
		elif re.search('^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$', address):
			type = "IPADDRESS"
		else:
			raise Exception('Invalid IP address format ' + address)

		# Mark changed
		self.changed = True
		if self.module.check_mode:
			return

		# REST call to Security Directory to add address
		xml = self.add_address_xml.render(address=address, type=type)
		node = self.url('post', '/api/juniper/sd/address-management/addresses', headers=self.address_content_type_header, data=xml)
		result = dict(name=node.find('name').text, id=node.find('id').text, type=node.find('address-type').text, prefix=address)
		return result

	def check_add_address(self, address):
		logging.debug('Getting address reference: %s' % address)
		node = self.url('get', '/api/juniper/sd/address-management/addresses').find('./address[ip-address="' + address + '"]')

		if node is not None:
			result = dict(name=node.find('./name').text, id=node.find('./id').text, type=node.find('./address-type').text, prefix=address)
		else:
			logging.debug('Address %s not found!, adding it to SD' % address)
			result = self.add_address(address)
		return result
		
	def check_service(self, service):
		logging.debug('Getting service reference: %s' % service)
		node = self.url('get', '/api/juniper/sd/service-management/services?filter=(global eq \'' + service + '\')').find('./service[name="' + service + '"]')

		if node is not None:
			result = dict(name=node.find('./name').text, id=node.find('./id').text)
			return result
		else:
			raise Exception('Service not found')
	
	def get_device(self, device, add_rule):
		if add_rule:
			# Get Source Address References, Add it if not found
			if not isinstance(self.source_addresses, list):
				self.source_addresses = [ self.source_addresses ]
			self.source_info = { self.source_zone : [self.check_add_address(addr) for addr in self.source_addresses] }
			
			# Get Destination Address References, Add it if not found
			if not isinstance(self.destination_addresses, list):
				self.destination_addresses = [ self.destination_addresses ]
			self.destination_info = { self.destination_zone : [ self.check_add_address(addr) for addr in self.destination_addresses ] }
						  
			# Get Services References
			if not isinstance(self.services, list):
				self.services = [ self.services ]
			self.services_info = [ self.check_service(service) for service in self.services ]
	
		if device is not None:
			logging.debug('Getting device reference: %s' % device)
			node = self.url('get', '/api/juniper/sd/device-management/devices').find('./device[name="' + device + '"]')

			if node is not None:
				result = dict(  name=node.find('./name').text, 
								id=node.find('./id').text, 
								policy_name=node.find('./assigned-services/assigned-service[type="POLICY"]/name').text
								)
				if add_rule:
					result.update(dict(	source_zone=self.source_info,
										destination_zone=self.destination_info,
										services=self.services_info
										))
				return [ result ]
			else:
				raise Exception('Device not found')
		else:
			logging.debug('Auto fetching the device list and zone info from Junos Space script')
		
			nodes = self.url('get', '/api/juniper/sd/device-management/devices').findall('./device')
			if add_rule:
				if len(nodes) > 0:
					result = [ dict(name=node.find('./name').text, 
									id=node.find('./id').text, 
									policy_name=node.find('./assigned-services/assigned-service[type="POLICY"]/name').text,
									services=self.services_info
									) for node in nodes ]
				else:
					raise Exception('Device not found')
					
				# Fetch the script info
				node = self.url('get', '/api/space/script-management/scripts').find('./script[scriptName="sd-demo-get-zone.slax"]')
				if node is not None:
					script_id = node.find('./id').text
				else:
					raise Exception('Get zone script not found')

				# Execute script on each device
				root = self.url('get', '/api/space/device-management/devices')
				for dev in result:
					node = root.find('./device[name="' + dev['name'] + '"]')
					if node is not None:
						dev['space_platform_id'] = node.get('key')
					else:
						raise Exception('SD device not found in Space')

					xml = self.exec_scripts_xml.render(script_id=script_id, device_id=dev['space_platform_id'], address_list=','.join(self.source_addresses + self.destination_addresses), default_route=True)
					dev['script_task_id'] = self.url('post', '/api/space/script-management/scripts/exec-scripts', headers=self.exec_scripts_content_type_header, data=xml).find('./id').text
				
				# Get the script result & analyse the data
				for dev in result:
					if self.wait_for_job_complete(dev['script_task_id']) == "SUCCESS":
						logging.debug('Get zone info success for %s' % dev['name'])
						job_result = self.url('get', '/api/space/script-management/job-instances/' + dev['script_task_id'] + '/script-mgmt-job-results').find('./script-mgmt-job-result/job-remarks').text
						job_result = re.search(r'<output>(.*)</output>', job_result, re.DOTALL).group(1)
						route = {}
						for line in job_result.splitlines():
							item = line.split('|')
							field = [ 'table', 'route', 'nh-intf', 'zone' ]
							route[item[0]] = dict(zip(field, item[1:]))
						for src in self.source_addresses:
							for dst in self.destination_addresses:
								if route.get(src) and route.get(dst) and route[src]['nh-intf'] != route[dst]['nh-intf'] and route[src]['table'] == route[dst]['table']:
									if not dev.get('source_zone'): dev['source_zone'] = {}
									if not dev.get('destination_zone'): dev['destination_zone'] = {}
									if not dev['source_zone'].get(route[src]['zone']): dev['source_zone'][route[src]['zone']] = set()
									if not dev['destination_zone'].get(route[dst]['zone']): dev['destination_zone'][route[dst]['zone']] = set()
									dev['source_zone'][route[src]['zone']].add(src)
									dev['destination_zone'][route[dst]['zone']].add(dst)
						if dev.get('source_zone') and dev.get('destination_zone'):
							for zone in dev['source_zone']:
								dev['source_zone'][zone] = [ zone_info for zone_info in self.source_info.values()[0] if zone_info['prefix'] in dev['source_zone'][zone] ]
							for zone in dev['destination_zone']:
								dev['destination_zone'][zone] = [zone_info for zone_info in self.destination_info.values()[0] if zone_info['prefix'] in dev['destination_zone'][zone] ]
				
				result = [ dev for dev in result if dev.get('source_zone') and dev.get('destination_zone') ]
			else:
				if len(nodes) > 0:
					result = [ dict(name=node.find('./name').text, 
									id=node.find('./id').text, 
									policy_name=node.find('./assigned-services/assigned-service[type="POLICY"]/name').text
									) for node in nodes ]
				else:
					raise Exception('Device not found')
			
			return result

	def get_policy(self, device):
		node = self.url('get', '/api/juniper/sd/fwpolicy-management/firewall-policies?filter=(global eq \'' + device['policy_name'] + '\')').find('./firewall-policy[type="DEVICE"]')
		if node is not None:
			policy_id = node.find('./id').text
		else:
			raise Exception('Policy not found')
		
		#search policy edit version
		edit_version = self.url('get', '/api/juniper/sd/fwpolicy-management/firewall-policies/' + policy_id).find('./edit-version').text
		#search policy zone rule id
		zone_rule_id = self.url('get', '/api/juniper/sd/fwpolicy-management/firewall-policies/' + policy_id + '/firewall-rules').find('./firewall-rule[rule-group-type="ZONE"]/id').text
		#search device rule id
		device_rule_id = self.url('get', '/api/juniper/sd/fwpolicy-management/firewall-rules/' + zone_rule_id + '/members').find('./firewall-rule[rule-group-type="DEVICE"]/id').text
		
		return dict(policy_id=policy_id, edit_version=edit_version, zone_rule_id=zone_rule_id, device_rule_id=device_rule_id )
	
	def publish_policy(self, policy_id):
		xml = self.publish_policy_xml.render(policy_id = policy_id)
		task_id = self.url('post', '/api/juniper/sd/fwpolicy-management/publish', headers=self.publish_policy_content_type_header, data=xml).find('id').text
		self.wait_for_job_complete(task_id)

	def update_device(self, device_id):
		xml = self.update_devices_xml.render(device_id = device_id)
		return self.url('post', '/api/juniper/sd/device-management/update-devices', headers=self.update_devices_content_type_header, data=xml).find('id').text
	
	def lock_policy(self, policy_id):
		# REST call to acquire lock
		return self.url('post', '/api/juniper/sd/fwpolicy-management/firewall-policies/' + policy_id + '/lock', get_cookie=True)
			
	def unlock_policy(self, policy_id, cookies):
		# REST call to release lock
		self.url('post', '/api/juniper/sd/fwpolicy-management/firewall-policies/' + policy_id + '/unlock', cookies=cookies)

	def create_change_request(self, policy_id, policy_name, cookies):
		logging.debug('Creating change request ID for policy id %s' % policy_id)
		
		cr_name = self.change_request_id + '-' + policy_name
		xml = self.create_cr_xml.render(priority = 'LOW',
										description = 'Created by SD API',
										policy_id = policy_id,
										due_date = str(int(time.time())+86400)+'000',
										cr_name = cr_name
										)
		self.url('post', '/api/juniper/sd/change-request-management/create-async', headers=self.create_cr_content_type_header, data=xml, cookies=cookies)
			
		while True:
			time.sleep (1)
			node = self.url('get', '/api/juniper/sd/change-request-management/change-requests').find('./change-request[name="' + cr_name + '"][policy-id="' + policy_id + '"]')
			if node is not None:
				cr_id = node.find('./id').text
				break
		return cr_id

	def approve_change_request(self, cr_id):
		logging.debug('Approve change request ID %s' % cr_id)

		xml = self.approve_cr_xml.render( cr_id = cr_id, comments = 'Auto approved by SD API')
		self.url('post', '/api/juniper/sd/change-request-management/approve-change-requests', headers=self.approve_cr_content_type_header, data=xml)
		
	def deploy_change_request(self, cr_id):
		logging.debug('Deploy change request ID %s' % cr_id)
		
		xml = self.deploy_cr_xml.render()
		node = self.url('post', '/api/juniper/sd/change-request-management/change-requests/' + cr_id + '/deploy', headers=self.deploy_cr_content_type_header, data=xml)
		return node.find('./monitorable-task-instance-managed-object[operation="updateDevicesForCRJob"]/id').text

	def commit_rule_change(self, device):
		#if using change request workflow
		if self.change_control_workflow:
			logging.debug('Using Change Request Workflow')
			
			# Create Change Request
			device['cr_id'] = self.create_change_request(device['policy_id'], device['policy_name'], self.cookies)
			
			# Approve Change Request
			self.approve_change_request(device['cr_id'])
			
			# Deploy Change Request
			device['update_task_id'] = self.deploy_change_request(device['cr_id'])
		
		else:
			# Releasing Lock
			logging.debug('Releasing lock for policy %s' % device['policy_name'])
			self.unlock_policy(policy['policy_id'], self.cookies)

			# Publish Policy
			if self.publish:
				logging.debug('Publishing policy %s' % device['policy_name'])
				self.publish_policy(policy['policy_id'])
		
			# Update Device
			if self.update_devices:
				logging.debug('Updating Device %s' % device['id'])
				device['update_task_id'] = self.update_device(device['id'])

	def del_rule(self):
		device_objs = self.get_device(self.device, add_rule=False)
		
		for device in device_objs:
			device.update(self.get_policy(device))
			node = self.url('get', '/api/juniper/sd/fwpolicy-management/firewall-rules/' + device['device_rule_id'] + '/members').findall('./firewall-rule[name="' + self.change_request_id + '"]')

			if node is not None:
				rules = [ rule.find('./id').text for rule in node ]
				
				if rules:
					self.changed = True
					if self.module.check_mode:
						return

					# Acquiring Lock
					logging.debug('Acuiring lock for policy %s' % device['policy_name'])
					self.cookies = self.lock_policy(device['policy_id'])
					
					# Update Policy
					xml = self.delete_rules_xml.render( policy_id = device['policy_id'],
														policy_edit_ver = device['edit_version'],
														rules = rules
														)
					#logging.debug('Dumping policy xml %s' % xml)
					logging.debug('Modifying policy %s' % device['policy_name'])
					self.url('post', '/api/juniper/sd/fwpolicy-management/modify-rules', headers=self.modify_rules_content_type_header, data=xml, cookies=self.cookies)
					
					self.commit_rule_change(device)
				
		for device in device_objs:
			if device.get('update_task_id'):
				self.wait_for_job_complete(device['update_task_id'])
	
	def add_rule(self):
		# Check the optional parameters, but mandatory for add rule
		if not (self.source_addresses and self.destination_addresses and self.services):
			raise Exception('Mandatory parameters for adding rule are missing')
	
		# Get Object References
		device_objs = self.get_device(self.device, add_rule=True)
		
		for device in device_objs:
			device.update(self.get_policy(device))

			# check if rules already exist
			node = self.url('get', '/api/juniper/sd/fwpolicy-management/firewall-rules/' + device['device_rule_id'] + '/members').find('./firewall-rule[name="' + self.change_request_id + '"]')
			
			#if rules object exists
			if node is not None:
				logging.warning('Firewall rules for change request %s already existed' % self.change_request_id)
			else :
				# add policy rules
				# Mark changed
				self.changed = True
				if self.module.check_mode:
					return

				# Acquiring Lock
				logging.debug('Acquiring lock for policy %s' % device['policy_name'])
				self.cookies = self.lock_policy(device['policy_id'])

				# Update Policy
				xml = self.modify_rules_xml.render( rule_name   = self.change_request_id,
													src_zone    = device['source_zone'],
													dst_zone    = device['destination_zone'],
													srv_objs    = device['services'],
													policy_name = device['policy_name'],
													device_rule_id = device['device_rule_id'],
													policy_id = device['policy_id'],
													policy_edit_ver = device['edit_version']
													)
				logging.debug('Modifying policy %s' % device['policy_name'])
				self.url('post', '/api/juniper/sd/fwpolicy-management/modify-rules', headers=self.modify_rules_content_type_header, data=xml, cookies=self.cookies)
				
				self.commit_rule_change(device)

		for device in device_objs:
			if device.get('update_task_id'):
				self.wait_for_job_complete(device['update_task_id'])

	def if_changed(self):
		return self.changed
# ===========================================

def main():
	logging.basicConfig(filename="/tmp/sdapi.log",level=logging.DEBUG)
	logging.getLogger('requests').setLevel(logging.CRITICAL)
	
	module = AnsibleModule(
		argument_spec = dict(
			junosspace_host = dict(required=True),
			junosspace_username = dict(required=True),
			junosspace_password = dict(required=True),
			change_request_id = dict(required=True),
			device = dict(required=False),
			action = dict(default='add', choices=['add', 'del']),
			publish = dict(default=True, type='bool'),
			change_control_workflow = dict(default=False, type='bool'),
			update_devices = dict(default=True, type='bool'),
			source_addresses = dict(required=True),
			source_zone = dict(required=False),
			destination_addresses = dict(required=True),
			destination_zone = dict(required=False),
			services = dict(required=True),
		),
		supports_check_mode = True,
		required_together = [['device','source_zone','destination_zone']],
	)
	sdapi = Sdapi(module)
	 
	if module.check_mode:
	# Check if any changes would be made but don't actually make those changes
		module.exit_json(changed=True)

	if sdapi.action == "add":
		sdapi.add_rule()
		module.exit_json(changed=sdapi.if_changed())

	elif sdapi.action == "del":
		sdapi.del_rule()
		module.exit_json(changed=sdapi.if_changed())
		
# import module snippets
from ansible.module_utils.basic import *
if __name__ == '__main__':
	main()

