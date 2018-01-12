
# meltdown

#### Table of Contents

1. [Description](#description)
2. [Setup - The basics of getting started with meltdown](#setup)
4. [Reference - An under-the-hood peek at what the module is doing and how](#reference)
5. [Limitations - OS compatibility, etc.](#limitations)
6. [Development - Guide for contributing to the module](#development)

## Description

meltdown detects whether your system is vulnerable for Meltdown (CVE-2017-5754) or Spectre (CVE-2017-5753, CVE-2017-5715) vulnerabilities. It then offers some tasks and manifests which help remediate the vulnerability.

meltdown for Linux uses the script ``spectre-meltdown-checker.sh`` by Vivek Gite - see https://www.cyberciti.biz/faq/check-linux-server-for-spectre-meltdown-vulnerability/ - all credits to him for that awesome script.

## Setup

The only thing needed is to install the module on the puppetmaster (for instance, by adding it to Puppetfile). During the next puppet run, all connected agents will receive meltdown's facts definitions and will send meltdown's facts back to the puppetmaster.

## Reference

meltdown provides the following facts:

### meltdown (Linux)

This is a json object of the following form, as returned from ``spectre-meltdown-checker.sh``
```
[
  {
    "NAME": "SPECTRE VARIANT 1",
    "CVE": "CVE-2017-5753",
    "VULNERABLE": false,
    "INFOS": "106 opcodes found, which is >= 70, heuristic to be improved when official patches become available"
  },
  {
    "NAME": "SPECTRE VARIANT 2",
    "CVE": "CVE-2017-5715",
    "VULNERABLE": true,
    "INFOS": "IBRS hardware + kernel support OR kernel with retpoline are needed to mitigate the vulnerability"
  },
  {
    "NAME": "MELTDOWN",
    "CVE": "CVE-2017-5754",
    "VULNERABLE": false,
    "INFOS": "PTI mitigates the vulnerability"
  }
]
```
### cve-2017-5754 (Linux)

This facts contains the value `true` if the vulnerability is detected and `false` otherwize.

### cve-2017-5753 (Linux)

This facts contains the value `true` if the vulnerability is detected and `false` otherwize.

### cve-2017-5715 (Linux)

This facts contains the value `true` if the vulnerability is detected and `false` otherwize.

Meltdown provides the following tasks:

### meltdown::kernel_upgrade

This task offers 2 parameters:
*force*  : if true, the kernel upgrade is really performed, otherwise it only outputs what it would have done
*reboot* : if true, reboots the machine after update, but only if *force* is also true

## Limitations

meltdown is tested on the following platforms:

* Linux
  * CentOS/Red Hat 7 (but should work on earlier versions)
* Windows (versions?)

Feel free to add support for other platforms.

## Development

Contributions for adding other platforms are welcomed.