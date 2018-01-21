
# meltdown

#### Table of Contents

1. [Description](#description)
2. [Setup - The basics of getting started with meltdown](#setup)
4. [Reference - An under-the-hood peek at what the module is doing and how](#reference)
5. [Limitations - OS compatibility, etc.](#limitations)
6. [Development - Guide for contributing to the module](#development)

## Description

This module detects whether your system is vulnerable for Meltdown (CVE-2017-5754) or Spectre (CVE-2017-5753, CVE-2017-5715) vulnerabilities. It then offers some tasks and manifests which help remediate the vulnerability. 

*NOTE*: full remediation also requires patching your hardware and/or virtualization platforms. Please refer to specific instructions for your vendors and consider patches carefully before applying.

*NOTE*: this module is provided in the hope it will be useful, but does not guarantee correct or complete detection or remediation of Meltdown / Spectre. Use it at your own discretion.

The module uses some code created by others, which we'd like to recognize here:

For Linux, the module uses the script ``spectre-meltdown-checker.sh`` by Stéphane Lesimple - see https://github.com/speed47/spectre-meltdown-checker - all credits to him for that awesome script.

For Windows, the module uses the SpeculationControl module for Powershell - see https://www.powershellgallery.com/packages/SpeculationControl/1.0.4 and the Get-WUInstall function from Alexander Tsirel - see https://github.com/noma4i/puppet-windows_updates. All credits to them for these awesome scripts.

## Setup

To get information (facts) only, just install the module on the puppetmaster (either manually or by adding it to Puppetfile). During the next puppet run, all connected agents will receive meltdown's facts definitions and will send meltdown's facts back to the puppetmaster.

This module includes two manifests to aid in some prerequisites that you can manage with Puppet.

## Reference

### Classes

#### meltdown::linux

Ensures the prerequisite ``binutils`` package is present for properly detecting Spectre & Meltdown.

#### meltdown::windows

Ensures the registry entries are present that are needed to enable the Spectre & Meltdown hotfix after it is installed. These entries don't do anything on systems where the hotfix is not yet installed, so they can be applied to all Windows systems without negative consequences.

### Facts

meltdown provides the following facts:

#### meltdown

This is a json object of the following form:
```
  {
    "CVE-2017-5753" : {
      "CVE" : "2017-5753",
      "description" : "Spectre Variant 1",
      "info" : {
        <specific info relevant to your OS & hardware>
      },
      "vulnerable" : false
    },
    "CVE-2017-5715" : {
      "CVE" : "2017-5715",
      "description" : "Spectre Variant 2",
      "info" : {
        <specific info relevant to your OS & hardware>
      },
      "vulnerable" : true
    },
    "CVE-2017-5754" : {
      "CVE" : "2017-5754",
      "description" : "Spectre Variant 3 - also known as Meltdown",
      "info" : {
        <specific info relevant to your OS & hardware>
      },
      "vulnerable" : false
    }
  }
```

### Tasks

Meltdown provides the following tasks:

#### meltdown::linux_update

This task updates the Linux kernel to the latest version, which contains the patch for Spectre & Meltdown. The task offers 2 parameters:

* **force**  : if true, the kernel upgrade is actually performed, otherwise it only outputs what it would have done
* **reboot** : if true, reboots the machine after update, but only if *force* is also true

#### meltdown::windows_update

This task installs the correct Windows patch for Spectre & Meltdown for Windows Server 2008 R2, 2012 R2, 2016 and 2016 Server Core. The task offers 2 parameters:

* **force**  : if true, the patch installation is actually performed, otherwise it only outputs if the patch is being offered to this system from the update server
* **reboot** : if true, reboots the machine after update, but only if *force* is also true

If the patch is not being offered to the system from the update server, the task will notify you of this. If the reason for this is that a required registry entry is not present (which should already be set by your antivirus product), the task will notify you of this. You have the option of using the meltdown::force_offer_hotfix task to get this registry entry in place if needed.

#### meltdown::force_offer_update

This task will create the registry entry needed for the patch to be offered to the system by the update server. This entry should normally have already been set by your Antivirus product. If you are not running any Antivirus software, you can use this task to get the entry in place.
This task has no parameters.

## Limitations

meltdown is tested on the following platforms:

* Linux
  * CentOS 7
  * CentOS 6
  * Debian 8 64 bits
  * Debian 8 32 bits
  * Ubuntu 14.04
* Windows Server
  * Windows Server 2008 R2
  * Windows Server 2102 R2
  * Windows Server 2016

meltdown works on all Puppet Enterprise versions specified in the compatibility information, but tasks only work starting with 2017.3.

## Development

Contributions for adding other platforms and improving remediation use cases are welcomed.
