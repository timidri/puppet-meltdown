# meltdown

#### Table of Contents

1. [Description](#description)
1. [Setup - The basics of getting started with meltdown](#setup)
1. [Reference - An under-the-hood peek at what the module is doing and how](#reference)
1. [Limitations - OS compatibility, etc.](#limitations)
1. [Development - Guide for contributing to the module](#development)

## Description

This module detects whether your system is vulnerable for Meltdown and Spectre.

### Detection on Linux

On Linux, the module detects the following vulnerabilities (listed in alphabetical order):

* CVE-2017-5715 [branch target injection] aka 'Spectre Variant 2'
* CVE-2017-5753 [bounds check bypass] aka 'Spectre Variant 1'
* CVE-2017-5754 [rogue data cache load] aka 'Meltdown' aka 'Variant 3'
* CVE-2018-12126 [microarchitectural store buffer data sampling (MSBDS)] aka 'Fallout'
* CVE-2018-12127 [microarchitectural load port data sampling (MLPDS)] aka 'RIDL'
* CVE-2018-12130 [microarchitectural fill buffer data sampling (MFBDS)] aka 'ZombieLoad'
* CVE-2018-3615 [L1 terminal fault] aka 'Foreshadow (SGX)'
* CVE-2018-3620 [L1 terminal fault] aka 'Foreshadow-NG (OS)'
* CVE-2018-3639 [speculative store bypass] aka 'Variant 4'
* CVE-2018-3640 [rogue system register read] aka 'Variant 3a'
* CVE-2018-3646 [L1 terminal fault] aka 'Foreshadow-NG (VMM)'
* CVE-2019-11091 [microarchitectural data sampling uncacheable memory (MDSUM)] aka 'RIDL'

For Linux, the module uses the script ``spectre-meltdown-checker.sh`` by Stéphane Lesimple - see https://github.com/speed47/spectre-meltdown-checker - all credits to him for that awesome script.

### Detection on Windows

On Windows, the module detects the following vulnerabilities (listed in alphabetical order):

* CVE-2017-5715 Spectre Variant 2 (Branch Target Injection)
* CVE-2017-5753 Spectre Variant 1 (Bounds Check Bypass)
* CVE-2017-5754 Spectre Variant 3 - also known as Meltdown (Rogue Data Cache Load)
* CVE-2018-12126 Microarchitectural Store Buffer Data Sampling (MSBDS)
* CVE-2018-12127 Microarchitectural Fill Buffer Data Sampling (MFBDS)
* CVE-2018-12130 Microarchitectural Load Port Data Sampling (MLPDS)
* CVE-2018-3620 Spectre Variant 'Foreshadow' (L1 Terminal Fault)
* CVE-2018-3639 Spectre Variant 4 (Speculative Store Bypass)
* CVE-2019-11091 Microarchitectural Data Sampling Uncacheable Memory (MDSUM)
* CVE-2019-1125 Spectre variant 1 variant - SWAPGS

For Windows, the module uses the SpeculationControl module for Powershell - see https://www.powershellgallery.com/packages/SpeculationControl/1.0.14 and the Get-WUInstall function from Michal Gajda - see https://github.com/noma4i/puppet-windows_updates. All credits to the authors for these awesome functions.

### Usage Warnings

*NOTE*: full remediation also requires patching your hardware and/or virtualization platforms. Please refer to specific instructions for your vendors and consider patches carefully before applying.

*NOTE*: this module is provided in the hope it will be useful, but does not guarantee correct or complete detection or remediation of Meltdown / Spectre. Use it at your own discretion.

## Setup

To get information (fact) only, just install the module on the Puppetmaster (either manually or by adding it to Puppetfile). During the next Puppet run, all connected agents will receive meltdown's fact definition and will send meltdown's fact back to the puppetmaster.

This module includes two manifests to aid in some prerequisites that you can manage with Puppet.

## Reference

### Classes

#### meltdown

Includes `meltdown::linux` or `meltdown::windows`, depending on the kernel.

#### meltdown::linux

Ensures the prerequisite ``binutils`` package is present for properly detecting Spectre & Meltdown.

#### meltdown::windows

Ensures the registry entries are present that are needed to enable the Spectre & Meltdown hotfix after it is installed. These entries don't do anything on systems where the hotfix is not yet installed, so they can be applied to all Windows systems without negative consequences.

### Facts

meltdown provides the following fact:

#### meltdown

This is a json object of the following form:
```
  {
    "CVE-2017-5753" : {
      "CVE" : "2017-5753",
      "description" : "Spectre Variant 1 (Bounds Check Bypass)",
      "info" : {
        <specific info relevant to your OS & hardware>
      },
      "vulnerable" : false
    },
    "CVE-2017-5715" : {
      "CVE" : "2017-5715",
      "description" : "Spectre Variant 2 (Branch Target Injection)",
      "info" : {
        <specific info relevant to your OS & hardware>
      },
      "vulnerable" : true
    },
    "CVE-2017-5754" : {
      "CVE" : "2017-5754",
      "description" : "Spectre Variant 3 - also known as Meltdown  (Rogue Data Cache Load)",
      "info" : {
        <specific info relevant to your OS & hardware>
      },
      "vulnerable" : true
    },
    "CVE-2018-3620" : {
      "CVE" : "2018-3620",
      "description" : "Spectre Variant (L1 Terminal Fault)",
      "info" : {
        <specific info relevant to your OS & hardware>
      },
      "vulnerable" : true
    },
    "CVE-2018-3639" : {
      "CVE" : "2018-3639",
      "description" : "Spectre Variant 4 (Speculative Store Bypass)",
      "info" : {
        <specific info relevant to your OS & hardware>
      },
      "vulnerable" : true
    },
    "CVE-2019-1125" : {
      "CVE" : "2019-1125",
      "description" : "Spectre variant 1 variant - SWAPGS",
      "info" : {
        <specific info relevant to your OS & hardware>
      },
      "vulnerable" : false
    },
    "CVE-2018-12126" : {
      "CVE" : "2018-12126",
      "description" : "Microarchitectural Store Buffer Data Sampling (MSBDS)",
      "info" : {
        <specific info relevant to your OS & hardware>
      },
      "vulnerable" : true
    },
    "CVE-2018-12127" : {
      "CVE" : "2018-12127",
      "description" : "Microarchitectural Fill Buffer Data Sampling (MFBDS)",
      "info" : {
        <specific info relevant to your OS & hardware>
      },
      "vulnerable" : true
    },
    "CVE-2018-12130" : {
      "CVE" : "2018-12130",
      "description" : "Microarchitectural Load Port Data Sampling (MLPDS)",
      "info" : {
        <specific info relevant to your OS & hardware>
      },
      "vulnerable" : true
    },
    "CVE-2019-11091" : {
      "CVE" : "2019-11091",
      "description" : "Microarchitectural Data Sampling Uncacheable Memory (MDSUM)",
      "info" : {
        <specific info relevant to your OS & hardware>
      },
      "vulnerable" : true
    },
  }
```

### Tasks

Meltdown provides the following tasks:

#### meltdown::linux_update

This task updates the Linux kernel to the latest version, which contains the patch for Spectre & Meltdown. The task offers 2 parameters:

* **force**  : if true, the kernel upgrade is actually performed, otherwise it only outputs what it would have done
* **reboot** : if true, reboots the machine after update, but only if *force* is also true

#### meltdown::windows_update

This task installs the correct Windows patch for Spectre & Meltdown for Windows Server 2008 R2, 2012 R2, 2016 and 2016 Server Core. The task offers 3 parameters:

* **fallbacktowu**  : If true, updates can be retrieved from Windows Update directly if they are not provided by the WSUS server 
* **force**  : if true, the patch installation is actually performed, otherwise it only outputs if the patch is being offered to this system from the update server
* **reboot** : if true, reboots the machine after update, but only if *force* is also true

If the patch is not being offered to the system from the update server, the task will notify you of this. If the reason for this is that a required registry entry is not present (which should already be set by your antivirus product), the task will notify you of this. You have the option of using the meltdown::force_offer_hotfix task to get this registry entry in place if needed. If the reason for not offering the patch is because of certain prerequired patches not being installed, the task will also notify you of this. If the 'force' option is enabled, the needed prerequired patch will be installed first, after which you can retry to retrieve & install the Spectre/Meltdown patch.

#### meltdown::force_offer_update

This task will create the registry entry needed for the patch to be offered to the system by the update server. This entry should normally have already been set by your Antivirus product. If you are not running any Antivirus software, you can use this task to get the entry in place.
This task has no parameters.

## Limitations

meltdown works on all Puppet Enterprise versions specified in the compatibility information, but tasks only work starting with 2017.3. You can use the tasks in this module with Puppet Bolt as well.

## Development

Contributions for adding other platforms and improving remediation use cases are welcomed.
