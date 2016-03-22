# sdapi-ansible

This module is for managing Juniper SRX firewalls with security director 15.1 thru ansible scripts. 

key features of this module:
1. Add aAddress objects
2. Add/Remove permit firewall Rules to an existing policy. e.g. 10.1.1.1 zone A to 20.1.1.1 zone B service HTTP
3. Update firewall policies on relavent firewalls by route comparison
4. Change Control Workflow in Security Director 15.1
5. Update Security 

Here's the sample update playbook:

---
- name: test sdapi ansible module
  hosts: localhost
  connection: local
  gather_facts: no
  tasks: 
  - name: Add, Publish Firewall Policy
    sdapi:    
      junosspace_host: junosspace1.demo.net
      junosspace_username: super
      junosspace_password: juniper123
      change_request_id: cr00123
      device: labsrx
      source_zone: zone_a
      source_addresses: ['10.1.1.1', '10.1.1.2', '10.1.1.3', '10.1.1.4']
      destination_zone: zone_b
      destination_addresses: ['20.1.1.1', '20.1.1.2']
      services: ['http', 'https'] 
      action: add
      publish: True
      update_devices: True
      change_control_workflow: True

