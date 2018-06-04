#!/bin/bash

VPFA_LOG=/var/log/vpfa
node_id=$(dmidecode --s system-uuid | uniq)
mkdir -p ${VPFA_LOG}
INPUT_CONFIG_FILE=${VPFA_LOG}/vtf_node_conf

#Avoid accidentally overwriting input file if running locally, but allow for updates
if [[ -f ${INPUT_CONFIG_FILE} ]]; then
    vpp_conf_curr=`cat ${INPUT_CONFIG_FILE}`
    if [[ "$vpp_conf_curr" != "$vpp_conf" ]]; then
        mv ${INPUT_CONFIG_FILE} ${INPUT_CONFIG_FILE}_previous
    fi
fi
echo $vpp_conf > ${INPUT_CONFIG_FILE}
echo $vpp_conf | python -c "

# Start of Python script
# NOTE: Script relies on bash variable substitution for $node_id
# DO NOT USE DOUBLE QUOTES IN THE PYTHON CODE!

import ast
from ConfigParser import SafeConfigParser, NoOptionError, NoSectionError
import json
import os
import re
import subprocess
import six
import sys
import yaml
import time

VPFA_INIT = '/etc/vpe/vpfa/vpfa_init.sh'
DPDK_MAP = '/var/lib/os-net-config/dpdk_mapping.yaml'
UNDERLAY_IF_FILE = '/etc/vpe/vpfa/underlay_mac'
HIERA_DATA = '/etc/puppet/hieradata/${node_id}.json'
HIERA_SERVICE_CONFIG = '/etc/puppet/hieradata/service_configs.json'
OS_NET_CONF = '/etc/os-net-config/config.json'
LLDP_CONF = '/etc/vpe/lldp/lldp.conf'

dpdk_data = []
underlay_mac_intf = ''


def vpfa_init(env_params):
  # Launch vpfa_init script and config underlay mac
  print('Launching VPFA Init shell script')
  sproc = subprocess.Popen(VPFA_INIT.split(), env=dict(os.environ, **env_params))
  output, error = sproc.communicate()
  print('VPFA_INIT OUTPUT: {0}  ERROR: {1}'.format(output, error))


def load_dpdk_data(file):
  global dpdk_data
  try:
    with open(file, 'r') as f:
      dpdk_data = yaml.load(f)
  except IOError as e:
    print('WARNING: Stopping VPFA configuration. DPDK data load error: {}'.format(str(e)))
    sys.exit()


def mac_underlay_init(env_params, underlay_intf):
  # Assuming VPP configured by os-net-config module. Configure only underlay mac address file.

  print('INFO: Configuring underlay mac address for vpfa')
  if not underlay_intf:
    print('ERROR: VPFA MAC identifying underlay interface was not determined')
    raise ValueError('ERROR: VPFA MAC identifying underlay interface was not determined')

  for interface in dpdk_data:
    if 'name' in interface and interface['name'] == underlay_intf:
      underlay_mac = interface['mac_address']
      print('INFO: CustomVPFA Extra Config found underlay MAC address: {0}'
            ' for interface: {1}'.format(underlay_mac, interface['name']))
      break
  else:
    print('WARNING: CustomVPFA Extra Config unable to '
          'find dpdk_map MAC address for: {0}'.format(underlay_intf))
    return

  with open(UNDERLAY_IF_FILE, 'w') as umac_file:
    try:
      umac_file.write(underlay_mac)
      print('INFO: VPFA Extra Config wrote underlay mac file - OK')
    except IOError as e:
      print('ERROR: VPFA Extra Config underlay mac file error: {}'.format(str(e)))


def write_node_data(env_params):
  print('INFO: Extracting node specific data for vpfa and generating hiera file: {}'.format(str(HIERA_DATA)))
  node_env = env_params.get('NODE_DATA', {}).get('${node_id}', {})
  with open(HIERA_DATA, 'w') as hierafile:
    try:
      json.dump(node_env, hierafile, indent=2)
    except IOError as e:
      print('ERROR: VPFA Extra Config hiera node data file error: {}'.format(str(e)))
      raise e


def get_interfaces():
  # Get VPP interface data from Os Net config, combine it with DPDK map info and sort based on PCI address
  # The u_interface is taken to be the first one from the *configured* (unsorted) list order of bonded interfaces to
  # accomodate for the active-standby monding mode expressed in the configuration
  # For simple interfaces, it is the first one from the *sorted* list
  # NOTE: This requires a change indexing bonds when supporting multiple bonds

  print('INFO: Getting and augmenting VPP interface data')
  global underlay_mac_intf
  target_interfaces = []

  with open(OS_NET_CONF) as os_net_conf:
    try:
      config = json.load(os_net_conf)
      interfaces = config['network_config']
    except IOError as e:
      print('ERROR: VPFA Extra Config os-net-config file error: {}'.format(str(e)))
      raise e
  for i in interfaces:
    if i.get('type') in ['vpp_bond', 'vpp_interface']:
      target_interfaces.append(i)

  # This adds the pci_address key to the simple vpp_interfaces
  target_interfaces = merge_lists(target_interfaces, dpdk_data, 'name')
  target_interfaces = sorted(target_interfaces, key=lambda x: x.get('pci_address'))

  # This adds the pci_address key to the simple vpp_bond interfaces and sorts
  for i in target_interfaces:
    if i['type'] == 'vpp_bond':
      if not underlay_mac_intf:
        underlay_mac_intf = i['members'][0].get('name')
      _ = merge_lists(i['members'], dpdk_data, 'name')
      i['members'] = sorted(_, key=lambda x: x.get('pci_address'))
  # print('INFO: Target VPP Interfaces SORTED', target_interfaces)
  return target_interfaces


def update_with_intf_names(env_params, interfaces=[]):
  print('INFO: Extracting node vpp interface configuration')
  config = {}
  env_params['NODE_DATA']['${node_id}'].update({'cisco_vpfa::bond_if_list': []})
  env_params['NODE_DATA']['${node_id}'].update({'cisco_vpfa::underlay_interface': []})
  for i in interfaces:
    if i['type'] == 'vpp_bond':
      bond_nr = re.sub('[^0-9]', '', i['name'])
      env_params['NODE_DATA']['${node_id}']['cisco_vpfa::underlay_interface'].append('bond' + bond_nr)
      for member in i['members']:
        # NOTE: This requires a change indexing bonds when supporting multiple bonds
        env_params['NODE_DATA']['${node_id}']['cisco_vpfa::bond_if_list'].append(member['name'])
    if i['type'] == 'vpp_interface':
      env_params['NODE_DATA']['${node_id}']['cisco_vpfa::underlay_interface'].append(i['name'])
  return env_params

def update_with_lldp(env_params, interfaces=[]):
  # First Check if LLDP is meant to be configured
  with open(HIERA_SERVICE_CONFIG, 'r') as hiera_service_c:
    try:
      config = json.load(hiera_service_c)
    except IOError as e:
      print('ERROR: VPFA Extra Config os-net-config file error: {}'.format(str(e)))
      raise e
  if 'vts::lldp_enable' in config and config['vts::lldp_enable'] == True:
    print('INFO: Adding VPP LLDP config')
    # Add VPP LLDP enable command parametrized with puppet %fqdn fact
    env_params['NODE_DATA']['${node_id}'].update({'fdio::vpp_exec_commands':
                                       ['set lldp system-name %{::fqdn} tx-hold 4 tx-interval 30']})

    # Get the same IPv4 and IPv6 management addresses as used in the system LLDPD config
    lldp_mngmnt_ipv4 = '%{::ipaddress}'
    lldp_mngmnt_ipv6 = ''
    parser = SafeConfigParser()
    parser.read(LLDP_CONF)
    try:
      lldp_mngmnt_ipv4 = parser.get('DEFAULT', 'MGMT_IP4_ADDR')
      lldp_mngmnt_ipv6 = parser.get('DEFAULT', 'MGMT_IP6_ADDR')
    except (NoOptionError, NoSectionError) as e:
      print('WARNING: Couldn\'t obtain VTS LLDP management IP configuration: {} ...'.format(str(e)))
      print('... Setting Puppet facter\'s default IP as LLDP management IP address.')

    index_hack = 2

    LLDP_MGMT_STRING = ''
    if lldp_mngmnt_ipv4:
      LLDP_MGMT_STRING += ' mgmt-ip4 ' + lldp_mngmnt_ipv4
    if lldp_mngmnt_ipv6:
      LLDP_MGMT_STRING += ' mgmt-ip6 ' + lldp_mngmnt_ipv6

    for i in interfaces:
      if i['type'] == 'vpp_bond':
        for member in i['members']:
          env_params['NODE_DATA']['${node_id}']['fdio::vpp_exec_commands'].append(
            'set interface lldp sw_if_index ' + str(index_hack) + ' port-desc vtf:' + member['name']
            + LLDP_MGMT_STRING)
          index_hack += 1
        # NOTE: This requires a change when supporting multiple bonds
        break
        # return env_params
      if i['type'] == 'vpp_interface':
        env_params['NODE_DATA']['${node_id}']['fdio::vpp_exec_commands'].append(
          'set interface lldp sw_if_index ' + str(index_hack) + ' port-desc vtf:' + i['name'])
        index_hack += 1

  return env_params


def merge_lists(l1, l2, key):
  # Returns dict list l1 with additional data from dict list l2 only for shared keys, if any.
  kvals_l2 = [x.get(key) for x in l2]
  merged = {}
  for item in l1:
    merged[item[key]] = item
    if item[key] not in kvals_l2:
      continue
    for item2 in l2:
      if item[key] == item2[key]:
        merged[item[key]].update(item2)
  return [val for (_, val) in merged.items()]


#### Main script
print('\n*****************************************')
print('Cisco VTS Extra Pre Deployment script run')
print(time.strftime('%c'))
print('*****************************************\n')

input = sys.stdin.readline()
if input in ['\n', '\r']:
  print('No vpfa input passed. Skipping VTS Extra Pre Deployment script run.')
  sys.exit()
input = ast.literal_eval(input)
env_params = dict()
for i in input:
  env_params.update(i)

vpp_params = env_params.pop('VPP_PARAMS', {})
if isinstance(vpp_params, dict):
  for k, v in six.iteritems(vpp_params):
    env_params[k] = v
for k, v in six.iteritems(env_params):
  if isinstance(v, list):
    v = ','.join(v)
    env_params[k] = v

#Check if per-node id data is passed. If it isn't then VPFA config isn't needed
if '${node_id}' not in env_params['NODE_DATA'] and env_params['VPFA_INIT'] != True:
  print('No vpfa input passed for node: ${node_id}. Skipping VTS Extra Pre Deployment script run.')
  sys.exit()

# Create empty per-node data unless already present
if 'VPFA_INIT' in env_params and env_params['VPFA_INIT'] == True:
  # VPP config will be generated by vpfa_init script
  vpfa_init(env_params)
else:
  # VPP Config will be done by puppet. Need to add some config from os_net_conf data however.
  load_dpdk_data(DPDK_MAP)
  # Return list of vpp interfaces sorted based on PCI address and identify lead underlay MAC
  vpp_interfaces = get_interfaces()
  # Return environment parameters to be used for configuring hiera
  env_params = update_with_intf_names(env_params, vpp_interfaces)

  # If the underlay MAC interface was not picked from the bond, then select it here
  if not underlay_mac_intf:
    try:
      underlay_mac_intf = env_params['NODE_DATA']['${node_id}']['cisco_vpfa::underlay_interface'][0]
    except IndexError as e:
      print('No underlay mac interface could be determined from VPP data!')
      raise e
  mac_underlay_init(env_params, underlay_mac_intf)
  env_params = update_with_lldp(env_params, vpp_interfaces)

write_node_data(env_params)

# End of Python script

" >> ${VPFA_LOG}/vts_extra_config_pre_output