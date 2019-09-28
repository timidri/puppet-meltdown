Function Add-SpectreVariants {
    If ($PSVersionTable.PSVersion.Major -gt 2) {
        #This function adds CVE's for Spectre variants 1,2 and 3 (Meltdown)
        Import-Module $PSScriptRoot/SpeculationControl.psd1
        $SpeculationControl = Get-SpeculationControlSettings -Quiet

        if ([Environment]::OSVersion.Version.Major -ge 6) {
            $arrCVE.Add('CVE-2017-5753', @{
                "CVE"              = "2017-5753"
                "description"      = "Spectre Variant 1 (Bounds Check Bypass)"
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
                    "retpoline_enabled" = $SpeculationControl.BTIKernelRetpolineEnabled
                    "kernel_import_optimization_enabled" = $SpeculationControl.BTIKernelImportOptimizationEnabled
                }
            })
            $arrCVE.Add('CVE-2017-5754', @{
                "CVE"              = "2017-5754"
                "description"      = "Spectre Variant 3 - also known as Meltdown (Rogue Data Cache Load)"
                "vulnerable"       = if (!$SpeculationControl.KVAShadowRequired -or ($SpeculationControl.KVAShadowRequired -and $SpeculationControl.KVAShadowWindowsSupportEnabled)) {$False} else {$True}
                "info"             = @{
                    "hotfix_required" = $SpeculationControl.KVAShadowRequired
                    "hotfix_installed" = $SpeculationControl.KVAShadowWindowsSupportPresent
                    "hotfix_enabled" = $SpeculationControl.KVAShadowWindowsSupportEnabled
                    "pcid_optimizations_enabled" = $SpeculationControl.KVAShadowPcidEnabled
                }
            })
            $arrCVE.Add('CVE-2018-3639', @{
                "CVE"              = "2018-3639"
                "description"      = "Spectre Variant 4 (Speculative Store Bypass)"
                "vulnerable"       = if ($SpeculationControl.SSBDWindowsSupportEnabledSystemWide -or !$SpeculationControl.SSBDHardwareVulnerable) {$False} else {$True}
                "info"             = @{
                    "hotfix_installed" = $SpeculationControl.SSBDWindowsSupportPresent
                    "hotfix_enabled"   = $SpeculationControl.SSBDWindowsSupportEnabledSystemWide
                    "hardware_support" = $SpeculationControl.SSBDHardwarePresent
                    "hardware_vulnerable" = $SpeculationControl.SSBDHardwareVulnerable
                }
            })
            $arrCVE.Add('CVE-2018-3620', @{
                "CVE"              = "2018-3620"
                "description"      = "Spectre Variant 'Foreshadow' (L1 Terminal Fault)"
                "vulnerable"       = if ($SpeculationControl.L1TFWindowsSupportEnabled -or !$SpeculationControl.L1TFHardwareVulnerable) {$False} else {$True}
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
                "vulnerable"       = if ($SpeculationControl.MDSWindowsSupportEnabled -or !$SpeculationControl.MDSHardwareVulnerable) {$False} else {$True}
                "info"             = @{
                    "hotfix_installed" = $SpeculationControl.MDSWindowsSupportPresent
                    "hotfix_enabled"   = $SpeculationControl.MDSWindowsSupportEnabled
                    "hardware_vulnerable" = $SpeculationControl.MDSHardwareVulnerable
                }
            })
            $arrCVE.Add('CVE-2018-12126', @{
                "CVE"              = "2018-12126"
                "description"      = "Microarchitectural Store Buffer Data Sampling (MSBDS)"
                "vulnerable"       = if ($SpeculationControl.MDSWindowsSupportEnabled -or !$SpeculationControl.MDSHardwareVulnerable) {$False} else {$True}
                "info"             = @{
                    "hotfix_installed" = $SpeculationControl.MDSWindowsSupportPresent
                    "hotfix_enabled"   = $SpeculationControl.MDSWindowsSupportEnabled
                    "hardware_vulnerable" = $SpeculationControl.MDSHardwareVulnerable
                }
            })
            $arrCVE.Add('CVE-2018-12127', @{
                "CVE"              = "2018-12127"
                "description"      = "Microarchitectural Fill Buffer Data Sampling (MFBDS)"
                "vulnerable"       = if ($SpeculationControl.MDSWindowsSupportEnabled -or !$SpeculationControl.MDSHardwareVulnerable) {$False} else {$True}
                "info"             = @{
                    "hotfix_installed" = $SpeculationControl.MDSWindowsSupportPresent
                    "hotfix_enabled"   = $SpeculationControl.MDSWindowsSupportEnabled
                    "hardware_vulnerable" = $SpeculationControl.MDSHardwareVulnerable
                }
            })
            $arrCVE.Add('CVE-2018-12130', @{
                "CVE"              = "2018-12130"
                "description"      = "Microarchitectural Load Port Data Sampling (MLPDS)"
                "vulnerable"       = if ($SpeculationControl.MDSWindowsSupportEnabled -or !$SpeculationControl.MDSHardwareVulnerable) {$False} else {$True}
                "info"             = @{
                    "hotfix_installed" = $SpeculationControl.MDSWindowsSupportPresent
                    "hotfix_enabled"   = $SpeculationControl.MDSWindowsSupportEnabled
                    "hardware_vulnerable" = $SpeculationControl.MDSHardwareVulnerable
                }
            })
            $NTOSKRNL_version = (get-item $Env:SystemRoot\System32\ntoskrnl.exe).VersionInfo.ProductVersion
            $CVE_2019_1125_vulnerable = switch -Wildcard ((Get-WmiObject Win32_OperatingSystem).caption) {
               'Microsoft Windows Server 2008 Standard*' { if ($NTOSKRNL_version -gt '6.0.6003.20562') {$False} else {$True} }
               'Microsoft Windows Server 2008 Enterprise*' { if ($NTOSKRNL_version -gt '6.0.6003.20562') {$False} else {$True} }
               'Microsoft Windows Server 2008 Datacenter*' { if ($NTOSKRNL_version -gt '6.0.6003.20562') {$False} else {$True} }
               'Microsoft Windows Server 2008 R2*' { if ($NTOSKRNL_version -gt '6.1.7601.24499') {$False} else {$True} }
               'Microsoft Windows Server 2012 Standard*' { if ($NTOSKRNL_version -gt '6.2.9200.22794') {$False} else {$True} }
               'Microsoft Windows Server 2012 Datacenter*' { if ($NTOSKRNL_version -gt '6.2.9200.22794') {$False} else {$True} }
               'Microsoft Windows Server 2012 R2*' { if ($NTOSKRNL_version -gt '6.3.9600.19395') {$False} else {$True} }
               'Microsoft Windows Server 2016 *' {
                    $OSVersion = (Invoke-CimMethod -Namespace root\cimv2 -ClassName StdRegProv -MethodName GetSTRINGvalue -Arguments @{hDefKey=[uint32]2147483650; sSubKeyName='SOFTWARE\Microsoft\Windows NT\CurrentVersion'; sValueName='ReleaseId'}).sValue
                    switch ($OSVersion) {
                        '1607' { if ($NTOSKRNL_version -gt '10.0.14393.3085') {$False} else {$True} }
                        '1803' { if ($NTOSKRNL_version -gt '10.0.17134.885') {$False} else {$True} }
                        '1809' { if ($NTOSKRNL_version -gt '10.0.17763.615') {$False} else {$True} }
                    }
                }
                'Microsoft Windows Server 2019 *' { if ($NTOSKRNL_version -gt '10.0.17763.615') {$False} else {$True} }
            }
            $arrCVE.Add('CVE-2019-1125', @{
                "CVE"              = "2019-1125"
                "description"      = "Spectre variant 1 variant - SWAPGS"
                "vulnerable"       = $CVE_2019_1125_vulnerable
                "info"             = @{
                    "hotfix_installed" = !$CVE_2019_1125_vulnerable
                }
            })
        }
    }
}

function ConvertTo-Json20([object] $item){
    add-type -assembly system.web.extensions
    $ps_js=new-object system.web.script.serialization.javascriptSerializer
    return $ps_js.Serialize($item)
}

$arrCVE = @{}

If ($PSVersionTable.PSVersion.Major -gt 2) {
    Add-SpectreVariants
    $arrCVE | ConvertTo-Json
} Else {
    $cveIds=@("CVE-2018-12130", "CVE-2017-5715", "CVE-2018-3620", "CVE-2019-11091", "CVE-2018-3639", 
              "CVE-2019-1125", "CVE-2018-12127", "CVE-2017-5753", "CVE-2017-5754", "CVE-2018-12126")
    foreach ($cve in $cveIds) {
        $arrCVE.Add($cve, @{"error" = "Unable to check on Powershell 2.0, need at least 3.0"})
    }
    $arrCVE | ConvertTo-Json20
}
