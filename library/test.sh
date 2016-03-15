#!/bin/bash

~/sdapi-ansible/ansible/hacking/test-module -m sdapi.py -a "junosspace_host=junosspace1.kdc.jnpr.net device=labsrx source_zone=lab junosspace_password=juniper123 change_request_id=cr101 services=https destination_zone=jnpr junosspace_username=super source_addresses='[101.101.101.101, 101.101.101.102, 101.101.101.103]' destination_addresses=200.200.200.200"
