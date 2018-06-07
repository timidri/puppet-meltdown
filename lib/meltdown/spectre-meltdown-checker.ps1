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
            "description"      = "Spectre Variant 2"
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
            "description"      = "Spectre Variant 3 - also known as Meltdown"
            "vulnerable"       = if (!$SpeculationControl.KVAShadowRequired -or ($SpeculationControl.KVAShadowRequired -and $SpeculationControl.KVAShadowWindowsSupportEnabled)) {$False} else {$True}
            "info"             = @{
                "hotfix_installed" = $SpeculationControl.KVAShadowWindowsSupportPresent
                "hotfix_enabled"   = $SpeculationControl.KVAShadowWindowsSupportEnabled
                "hardware_support" = $SpeculationControl.KVAShadowPcidEnabled
                "hardware_support_required" = $SpeculationControl.KVAShadowRequired    
            }
        })
    }
}

$arrCVE = @{}
Add-SpectreVariants
$arrCVE | ConvertTo-Json
