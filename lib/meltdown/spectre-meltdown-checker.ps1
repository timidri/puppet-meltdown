Function Add-SpectreVariants {
    #This function adds CVE's for Spectre variants 1,2 and 3 (Meltdown)
    Import-Module $ENV:ProgramData\PuppetLabs\puppet\cache\lib\meltdown\SpeculationControl.psd1
    $SpeculationControl = Get-SpeculationControlSettings -Quiet

    if ([Environment]::OSVersion.Version.Major -ge 6) {
        $arrCVE.Add('CVE-2017-5753', @{
            "CVE"              = "2017-5753"
            "description"      = "Spectre Variant 1"
            "vulnerable"       = !$SpeculationControl.BTIWindowsSupportPresent
            "info"             = @{
                "hotfix_installed" = $SpeculationControl.BTIWindowsSupportPresent
            }
        })
        $arrCVE.Add('CVE-2017-5715', @{
            "CVE"              = "2017-5715"
            "description"      = "Spectre Variant 2 (Branch Target Injection)"
            "vulnerable"       = if ($SpeculationControl.BTIWindowsSupportEnabled) {$False} else {$True}
            "info"             = @{
                "hotfix_installed" = $SpeculationControl.BTIWindowsSupportPresent
                "hotfix_enabled"   = $SpeculationControl.BTIWindowsSupportEnabled
                "hardware_support" = $SpeculationControl.BTIHardwarePresent
                "hotfix_disable_due_to_lack_of_hardware_support" = $SpeculationControl.BTIDisabledByNoHardwareSupport
                "hotfix_disable_via_system_policy" = $SpeculationControl.BTIDisabledBySystemPolicy
            }
        })
        $arrCVE.Add('CVE-2017-5754', @{
            "CVE"              = "2017-5754"
            "description"      = "Spectre Variant 3 - also known as Meltdown (Rogue Data Cache Load)"
            "vulnerable"       = if (!$SpeculationControl.KVAShadowRequired -or ($SpeculationControl.KVAShadowRequired -and $SpeculationControl.KVAShadowWindowsSupportEnabled)) {$False} else {$True}
            "info"             = @{
                "hotfix_installed" = $SpeculationControl.KVAShadowWindowsSupportPresent
                "hotfix_enabled"   = $SpeculationControl.KVAShadowWindowsSupportEnabled
                "hardware_support" = $SpeculationControl.KVAShadowPcidEnabled
                "hardware_support_required" = $SpeculationControl.KVAShadowRequired
            }
        })
        $arrCVE.Add('CVE-2018-3639', @{
            "CVE"              = "2018-3639"
            "description"      = "Spectre Variant 4 (Speculative Store Bypass)"
            "vulnerable"       = if ($SSBDWindowsSupportEnabledSystemWide -or !$SSBDHardwareVulnerable) {$False} else {$True}
            "info"             = @{
                "hotfix_installed" = $SpeculationControl.SSBDWindowsSupportPresent
                "hotfix_enabled"   = $SpeculationControl.SSBDWindowsSupportEnabledSystemWide
                "hardware_support" = $SpeculationControl.SSBDHardwarePresent
                "hardware_vulnerable" = $SpeculationControl.SSBDHardwareVulnerable
            }
        })
        $arrCVE.Add('CVE-2018-3620', @{
            "CVE"              = "2018-3620"
            "description"      = "Spectre Variant (L1 Terminal Fault)"
            "vulnerable"       = if ($L1TFWindowsSupportEnabled -or !$L1TFHardwareVulnerable) {$False} else {$True}
            "info"             = @{
                "hotfix_installed" = $SpeculationControl.L1TFWindowsSupportPresent
                "hotfix_enabled"   = $SpeculationControl.L1TFWindowsSupportEnabled
                "hardware_vulnerable" = $SpeculationControl.L1TFHardwareVulnerable
                "invalid_pte_bit" = $SpeculationControl.L1TFInvalidPteBit
                "flush_supported" = $SpeculationControl.L1DFlushSupported
            }
        })
        $arrCVE.Add('CVE-2019-11091', @{
            "CVE"              = "2019-11091"
            "description"      = "Microarchitectural Data Sampling Uncacheable Memory (MDSUM)"
            "vulnerable"       = if ($MDSWindowsSupportEnabled -or !$MDSHardwareVulnerable) {$False} else {$True}
            "info"             = @{
                "hotfix_installed" = $SpeculationControl.MDSWindowsSupportPresent
                "hotfix_enabled"   = $SpeculationControl.MDSWindowsSupportEnabled
                "hardware_vulnerable" = $SpeculationControl.MDSHardwareVulnerable
            }
        })
        $arrCVE.Add('CVE-2018-12126', @{
            "CVE"              = "2018-12126"
            "description"      = "Microarchitectural Store Buffer Data Sampling (MSBDS)"
            "vulnerable"       = if ($MDSWindowsSupportEnabled -or !$MDSHardwareVulnerable) {$False} else {$True}
            "info"             = @{
                "hotfix_installed" = $SpeculationControl.MDSWindowsSupportPresent
                "hotfix_enabled"   = $SpeculationControl.MDSWindowsSupportEnabled
                "hardware_vulnerable" = $SpeculationControl.MDSHardwareVulnerable
            }
        })
        $arrCVE.Add('CVE-2018-12127', @{
            "CVE"              = "2018-12127"
            "description"      = "Microarchitectural Fill Buffer Data Sampling (MFBDS)"
            "vulnerable"       = if ($MDSWindowsSupportEnabled -or !$MDSHardwareVulnerable) {$False} else {$True}
            "info"             = @{
                "hotfix_installed" = $SpeculationControl.MDSWindowsSupportPresent
                "hotfix_enabled"   = $SpeculationControl.MDSWindowsSupportEnabled
                "hardware_vulnerable" = $SpeculationControl.MDSHardwareVulnerable
            }
        })
        $arrCVE.Add('CVE-2018-12130', @{
            "CVE"              = "2018-12130"
            "description"      = "Microarchitectural Load Port Data Sampling (MLPDS)"
            "vulnerable"       = if ($MDSWindowsSupportEnabled -or !$MDSHardwareVulnerable) {$False} else {$True}
            "info"             = @{
                "hotfix_installed" = $SpeculationControl.MDSWindowsSupportPresent
                "hotfix_enabled"   = $SpeculationControl.MDSWindowsSupportEnabled
                "hardware_vulnerable" = $SpeculationControl.MDSHardwareVulnerable
            }
        })
    }
}

$arrCVE = @{}
Add-SpectreVariants
$arrCVE | ConvertTo-Json
