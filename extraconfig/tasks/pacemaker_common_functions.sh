#!/bin/bash

set -eu

DEBUG="true" # set false if the verbosity is a problem
SCRIPT_NAME=$(basename $0)
function log_debug {
  if [[ $DEBUG = "true" ]]; then
    echo "`date` $SCRIPT_NAME tripleo-upgrade $(facter hostname) $1"
  fi
}

function is_bootstrap_node {
  if [ "$(hiera -c /etc/puppet/hiera.yaml bootstrap_nodeid)" = "$(facter hostname)" ]; then
    log_debug "Node is bootstrap"
    echo "true"
  fi
}

function check_resource_pacemaker {
  if [ "$#" -ne 3 ]; then
    echo_error "ERROR: check_resource function expects 3 parameters, $# given"
    exit 1
  fi

  local service=$1
  local state=$2
  local timeout=$3

  if [[ -z $(is_bootstrap_node) ]] ; then
    log_debug "Node isn't bootstrap, skipping check for $service to be $state here "
    return
  else
    log_debug "Node is bootstrap checking $service to be $state here"
  fi

  if [ "$state" = "stopped" ]; then
    match_for_incomplete='Started'
  else # started
    match_for_incomplete='Stopped'
  fi

  nodes_local=$(pcs status  | grep ^Online | sed 's/.*\[ \(.*\) \]/\1/g' | sed 's/ /\|/g')
  if timeout -k 10 $timeout crm_resource --wait; then
    node_states=$(pcs status --full | grep "$service" | grep -v Clone | { egrep "$nodes_local" || true; } )
    if echo "$node_states" | grep -q "$match_for_incomplete"; then
      echo_error "ERROR: cluster finished transition but $service was not in $state state, exiting."
      exit 1
    else
      echo "$service has $state"
    fi
  else
    echo_error "ERROR: cluster remained unstable for more than $timeout seconds, exiting."
    exit 1
  fi

}

function pcmk_running {
  if [[ $(systemctl is-active pacemaker) = "active" ]] ; then
    echo "true"
  fi
}

function is_systemd_unknown {
  local service=$1
  if [[ $(systemctl is-active "$service") = "unknown" ]]; then
    log_debug "$service found to be unkown to systemd"
    echo "true"
  fi
}

function grep_is_cluster_controlled {
  local service=$1
  if [[ -n $(systemctl status $service -l | grep Drop-In -A 5 | grep pacemaker) ||
      -n $(systemctl status $service -l | grep "Cluster Controlled $service") ]] ; then
    log_debug "$service is pcmk managed from systemctl grep"
    echo "true"
  fi
}


function is_systemd_managed {
  local service=$1
  #if we have pcmk check to see if it is managed there
  if [[ -n $(pcmk_running) ]]; then
    if [[ -z $(pcs status --full | grep $service)  && -z $(is_systemd_unknown $service) ]] ; then
      log_debug "$service found to be systemd managed from pcs status"
      echo "true"
    fi
  else
    # if it is "unknown" to systemd, then it is pacemaker managed
    if [[  -n $(is_systemd_unknown $service) ]] ; then
      return
    elif [[ -z $(grep_is_cluster_controlled $service) ]] ; then
      echo "true"
    fi
  fi
}

function is_pacemaker_managed {
  local service=$1
  #if we have pcmk check to see if it is managed there
  if [[ -n $(pcmk_running) ]]; then
    if [[ -n $(pcs status --full | grep $service) ]]; then
      log_debug "$service found to be pcmk managed from pcs status"
      echo "true"
    fi
  else
    # if it is unknown to systemd, then it is pcmk managed
    if [[ -n $(is_systemd_unknown $service) ]]; then
      echo "true"
    elif [[ -n $(grep_is_cluster_controlled $service) ]] ; then
      echo "true"
    fi
  fi
}

function is_managed {
  local service=$1
  if [[ -n $(is_pacemaker_managed $service) || -n $(is_systemd_managed $service) ]]; then
    echo "true"
  fi
}

function check_resource_systemd {

  if [ "$#" -ne 3 ]; then
    echo_error "ERROR: check_resource function expects 3 parameters, $# given"
    exit 1
  fi

  local service=$1
  local state=$2
  local timeout=$3
  local check_interval=3

  if [ "$state" = "stopped" ]; then
    match_for_incomplete='active'
  else # started
    match_for_incomplete='inactive'
  fi

  log_debug "Going to check_resource_systemd for $service to be $state"

  #sanity check is systemd managed:
  if [[ -z $(is_systemd_managed $service) ]]; then
    echo "ERROR - $service not found to be systemd managed."
    exit 1
  fi

  tstart=$(date +%s)
  tend=$(( $tstart + $timeout ))
  while (( $(date +%s) < $tend )); do
    if [[ "$(systemctl is-active $service)" = $match_for_incomplete ]]; then
      echo "$service not yet $state, sleeping $check_interval seconds."
      sleep $check_interval
    else
      echo "$service is $state"
      return
    fi
  done

  echo "Timed out waiting for $service to go to $state after $timeout seconds"
  exit 1
}


function check_resource {
  local service=$1
  local pcmk_managed=$(is_pacemaker_managed $service)
  local systemd_managed=$(is_systemd_managed $service)

  if [[ -n $pcmk_managed && -n $systemd_managed ]] ; then
    log_debug "ERROR $service managed by both systemd and pcmk - SKIPPING"
    return
  fi

  if [[ -n $pcmk_managed ]]; then
    check_resource_pacemaker $@
    return
  elif [[ -n $systemd_managed ]]; then
    check_resource_systemd $@
    return
  fi
  log_debug "ERROR cannot check_resource for $service, not managed here?"
}

function manage_systemd_service {
  local action=$1
  local service=$2
  log_debug "Going to systemctl $action $service"
  systemctl $action $service
}

function manage_pacemaker_service {
  local action=$1
  local service=$2
  # not if pacemaker isn't running!
  if [[ -z $(pcmk_running) ]]; then
    echo "$(facter hostname) pacemaker not active, skipping $action $service here"
  elif [[ -n $(is_bootstrap_node) ]]; then
    log_debug "Going to pcs resource $action $service"
    pcs resource $action $service
  fi
}

function stop_or_disable_service {
  local service=$1
  local pcmk_managed=$(is_pacemaker_managed $service)
  local systemd_managed=$(is_systemd_managed $service)

  if [[ -n $pcmk_managed && -n $systemd_managed ]] ; then
    log_debug "Skipping stop_or_disable $service due to management conflict"
    return
  fi

  log_debug "Stopping or disabling $service"
  if [[ -n $pcmk_managed ]]; then
    manage_pacemaker_service disable $service
    return
  elif [[ -n $systemd_managed ]]; then
    manage_systemd_service stop $service
    return
  fi
  log_debug "ERROR: $service not managed here?"
}

function start_or_enable_service {
  local service=$1
  local pcmk_managed=$(is_pacemaker_managed $service)
  local systemd_managed=$(is_systemd_managed $service)

  if [[ -n $pcmk_managed && -n $systemd_managed ]] ; then
    log_debug "Skipping start_or_enable $service due to management conflict"
    return
  fi

  log_debug "Starting or enabling $service"
  if [[ -n $pcmk_managed ]]; then
    manage_pacemaker_service enable $service
    return
  elif [[ -n $systemd_managed ]]; then
    manage_systemd_service start $service
    return
  fi
  log_debug "ERROR $service not managed here?"
}

function restart_service {
  local service=$1
  local pcmk_managed=$(is_pacemaker_managed $service)
  local systemd_managed=$(is_systemd_managed $service)

  if [[ -n $pcmk_managed && -n $systemd_managed ]] ; then
    log_debug "ERROR $service managed by both systemd and pcmk - SKIPPING"
    return
  fi

  log_debug "Restarting $service"
  if [[ -n $pcmk_managed ]]; then
    manage_pacemaker_service restart $service
    return
  elif [[ -n $systemd_managed ]]; then
    manage_systemd_service restart $service
    return
  fi
  log_debug "ERROR $service not managed here?"
}

function echo_error {
    echo "$@" | tee /dev/fd2
}

# swift is a special case because it is/was never handled by pacemaker
# when stand-alone swift is used, only swift-proxy is running on controllers
function systemctl_swift {
    services=( openstack-swift-account-auditor openstack-swift-account-reaper openstack-swift-account-replicator openstack-swift-account \
               openstack-swift-container-auditor openstack-swift-container-replicator openstack-swift-container-updater openstack-swift-container \
               openstack-swift-object-auditor openstack-swift-object-replicator openstack-swift-object-updater openstack-swift-object openstack-swift-proxy )
    local action=$1
    case $action in
        stop)
            services=$(systemctl | grep openstack-swift- | grep running | awk '{print $1}')
            ;;
        start)
            enable_swift_storage=$(hiera -c /etc/puppet/hiera.yaml tripleo::profile::base::swift::storage::enable_swift_storage)
            if [[ $enable_swift_storage != "true" ]]; then
                services=( openstack-swift-proxy )
            fi
            ;;
        *)  echo "Unknown action $action passed to systemctl_swift"
            exit 1
            ;; # shouldn't ever happen...
    esac
    for service in ${services[@]}; do
        manage_systemd_service $action $service
    done
}

# Special-case OVS for https://bugs.launchpad.net/tripleo/+bug/1635205
# Update condition and add --notriggerun for +bug/1669714
function special_case_ovs_upgrade_if_needed {
    # Always ensure yum has full cache
    yum makecache || echo "Yum makecache failed. This can cause failure later on."
    if rpm -qa | grep "^openvswitch-2.5.0-14" || rpm -q --scripts openvswitch | awk '/postuninstall/,/*/' | grep "systemctl.*try-restart" ; then
        echo "Manual upgrade of openvswitch - ovs-2.5.0-14 or restart in postun detected"
        rm -rf OVS_UPGRADE
        mkdir OVS_UPGRADE && pushd OVS_UPGRADE
        echo "Attempting to downloading latest openvswitch with yumdownloader"
        yumdownloader --resolve openvswitch
        for pkg in $(ls -1 *.rpm);  do
            if rpm -U --test $pkg 2>&1 | grep "already installed" ; then
                echo "Looks like newer version of $pkg is already installed, skipping"
            else
                echo "Updating $pkg with --nopostun --notriggerun"
                rpm -U --replacepkgs --nopostun --notriggerun $pkg
            fi
        done
        popd
    else
        echo "Skipping manual upgrade of openvswitch - no restart in postun detected"
    fi

}

# update os-net-config before ovs see https://bugs.launchpad.net/tripleo/+bug/1695893
function update_network() {
    set +e
    yum -q -y update os-net-config
    return_code=$?
    echo "yum update os-net-config return code: $return_code"

    # Writes any changes caused by alterations to os-net-config and bounces the
    # interfaces *before* restarting the cluster.
    os-net-config -c /etc/os-net-config/config.json -v --detailed-exit-codes

    RETVAL=$?
    if [[ $RETVAL == 2 ]]; then
        echo "os-net-config: interface configuration files updated successfully"
    elif [[ $RETVAL != 0 ]]; then
        echo "ERROR: os-net-config configuration failed"
        exit $RETVAL
    fi
    set -e

    # special case https://bugs.launchpad.net/tripleo/+bug/1635205 +bug/1669714
    special_case_ovs_upgrade_if_needed
}

# https://bugs.launchpad.net/tripleo/+bug/1704131 guard against yum update
# waiting for an existing process until the heat stack time out
function check_for_yum_lock {
    if [[ -f /var/run/yum.pid ]] ; then
        ERR="ERROR existing yum.pid detected - can't continue! Please ensure
there is no other package update process for the duration of the minor update
worfklow. Exiting."
        echo $ERR
        exit 1
   fi
}
