#!/bin/bash

update_redhat() {
    # echo "PT_force: ${PT_force}"
    yum_options='--assumeno'
    if [ "${PT_force}" == "true" ] ; then
        yum_options='--assumeyes'
    fi
    echo $yum_options
    yum update kernel $yum_options
}

update_debian() {
    # echo "PT_force: ${PT_force}"
    apt_options='--assume-no'
    if [ "${PT_force}" == "true" ] ; then
        apt_options='--assume-yes'
    fi
    echo $apt_options
    apt-get update
    apt-get $apt_options install linux-generic
}

reboot=""
if [ "$PT_force" == "true" ] ; then
  if [ "$PT_reboot" == "true" ] ; then
    reboot=true
  fi
fi

# try to detect linux flavour without puppet
if [ -f /etc/redhat-release ]; then
    update_redhat
elif [ -f /etc/lsb-release ]; then
    update_debian
else
    echo "unsupported operating system"
    exit 1
fi

if [ -n "$reboot" ]; then
    echo "Rebooting ..."
    shutdown -r
fi
