# Changelog

All notable changes to this project will be documented in this file.

## Release 0.9.8

**Features**

* Made boolean task parameters optional

## Release 0.9.7

**Features**

* Windows
  * Fixed the meltdown fact to also produce valid JSON on Windows 2008 / Powershell 2, although detection itself requires Powershell 3.0 or greater.
* Linux
  * Acceptance-tested on Debian 9 and Ubuntu 16.04 and 18.04
* Added acceptance test and Litmus support
* Added acceptance test to the travis CI pipeline
* Added appveyor CI pipeline to run acceptance test on Windows

## Release 0.9.6

**Features**

* Linux
  * Changed parameters of linux_update and windows_update tasks from Enum to Boolean
  * Updated `spectre-meltdown-checker.sh` to v0.42 (16AUG2019)
  * Updated README with full list of detected vulnerabilities

## Release 0.9.5

**Features**

* Windows
  * Updated `spectre-meltdown-checker.ps1` to latest version (8AUG2019)
  * Now includes CVE-2018-3639 [Variant 4 - Speculative Store Bypass]
  * Now includes CVE-2018-3620 [L1 terminal fault] aka 'Foreshadow & Foreshadow-NG'
  * Now includes CVE-2019-11091, CVE-2018-12126, CVE-2018-12127, CVE-2018-12130 [Microarchitectural Data Sampling]
  * Now includes CVE-2019-1125 [SWAPGS] (detection currently based on NTOSKRNL.EXE version)

## Release 0.9.4

**Features**

* Linux
  * Updated `spectre-meltdown-checker.sh` to latest v0.39 (13AUG2018)
  * Now includes CVE-2018-3615, CVE-2018-3620, CVE-2018-3646 [L1 terminal fault] aka 'Foreshadow & Foreshadow-NG'

## Release 0.9.3

**Features**

* Linux
  * Updated `spectre-meltdown-checker.sh` to latest v0.37+ (27MAY2018)
  * Now includes Variant 3a (CVE-2018-3640) and Variant 4 (CVE-2018-3639)
* Windows
  * Upgraded SpeculationControl PowerShell module to v1.0.7
  * Improved detection of the correct Spectre/Meltdown fix so that the fix can also be found in superseding updates.

**Bugfixes**

* Removed reliance on Hotfix IDs from detection for the meltdown fact in Windows (fixes false negatives). This is achieved by relying on the UpdateID instead of the KB article.
* Fixed detection of Windows Server 2016 v1709

## Release 0.9.2

**Features**

* Updated `spectre-meltdown-checker.sh` to v0.37+
* Replaced symbol keys in Linux fact value by strings

## Release 0.9.1

**Improvements**

* Made path to `spectre-meltdown-checker.ps1` script fully relative

## Release 0.9.0

**Features**

* Added support for Windows 2008 and Windows 2012, based on new patches provided by Microsoft
* Added 'FallbacktoWU' parameter for the meltdown::windows_update task (allows retrieval of patches from Windows Update)

## Release 0.8.6

**Features**

* Updated `spectre-meltdown-checker.sh` to v0.35

## Release 0.8.5

**Bugfixes**

* Fixed parameter type (was Boolean, is String now) in `windows_update.ps1`
* Now correctly crediting Michal Gajda for `Get-WUInstall`

## Release 0.8.4

**Features**

* Updated `spectre-meltdown-checker.sh` to v0.33+

**Bugfixes**

Documented class `meltdown`

## Release 0.8.3

**Bugfixes**

Updated CHANGELOG

## Release 0.8.2

**Features**

* Changed task parameters from `Boolean` to `Enum['true', 'false']`, so tasks are easier to use from the command line
* Updated `spectre-meltdown-checker.sh` to v0.32

**Bugfixes**

* Corrected version numbers in `metadata.json`
* Added proper task description to `linux_update.json`

## Release 0.8.1

**Features**

* Support for debian 8,both 32 and 64 bits.
* Support for EL6 (tested on Centos6).

**Bugfixes**

* Debian is now actually supported.

**Known Issues**

* Remediation for Linux is very naive right now, the task just updates the kernel package. This may or may not remediate anything on your specific version of the OS.
