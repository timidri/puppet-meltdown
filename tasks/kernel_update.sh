#!/bin/sh

# kernel_update
#
# This is where you put the shell code for your task.
#
# You can write Puppet tasks in any language you want and it's easy to 
# adapt an existing Python, PowerShell, Ruby, etc. script. Learn more at:
# http://puppet.com/docs/bolt/latest/converting_scripts_to_tasks.html 
# 
# Puppet tasks make it easy for you to enable others to use your script. Tasks 
# describe what it does, explains parameters and which are required or optional, 
# as well as validates parameter type. For examples, if parameter "instances" 
# must be an integer and the optional "datacenter" parameter must be one of 
# portland, sydney, belfast or singapore then the .json file 
# would include:
#   "parameters": {
#     "instances": {
#       "description": "Number of instances to create",
#       "type": "Integer"
#     }, 
#     "datacenter": {
#       "description": "Datacenter where instances will be created",
#       "type": "Enum[portland, sydney, belfast, singapore]"
#     }
#   }
# Learn more at: https://puppet.com/docs/bolt/latest/task_metadata.html
#

update_redhat() {
    yum_options='--assumeno'
    if [ "$PT_force" == "true" ] ; then
        yum_options='--assumeyes'
    fi
    echo $yum_options
    yum update kernel $yum_options
}

update_debian() {
    apt_options='--assume-no'
    if [ "$PT_force" == "true" ] ; then
        apt_options='--assume-yes'
    end
    echo $apt_options
    apt-get update
    apt-get $apt_options install linux-image
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
fi
