Import-Module $ENV:ProgramData\PuppetLabs\puppet\cache\lib\SpeculationControl.psd1
function global:Write-Host() {}
$SpeculationControl = Get-SpeculationControlSettings

$arrCVE = @{}
switch -Wildcard ((Get-WmiObject -class Win32_OperatingSystem).Caption) {
    'Microsoft Windows Server 2008 R2*'       { $hotfix = 'KB4056897' }
    'Microsoft Windows Server 2012 R2*'       { $hotfix = 'KB4056898' }
    'Microsoft Windows Server 2016*'          { $hotfix = 'KB4056890' }
    'Microsoft Windows Server, version 1709*' { $hotfix = 'KB4056892' }
}
if ($hotfix) {
    $arrCVE.Add('CVE-2017-5715', @{
        "hotfix_installed" = $SpeculationControl.BTIWindowsSupportPresent
        "hotfix_enabled"   = $SpeculationControl.BTIWindowsSupportEnabled
        "hardware_support" = $SpeculationControl.BTIHardwarePresent
        "compliant"        = if ($SpeculationControl.BTIWindowsSupportEnabled -and $SpeculationControl.BTIHardwarePresent) {$True} else {$False}
    })
    $arrCVE.Add('CVE-2017-5753', @{
        "hotfix_installed" = [bool](Get-WmiObject -query 'select * from win32_quickfixengineering' | ? HotFixID -eq $hotfix)
        "compliant"        = if ([bool](Get-WmiObject -query 'select * from win32_quickfixengineering' | ? HotFixID -eq $hotfix)) {$True} else {$False}
    })
    $arrCVE.Add('CVE-2017-5754', @{
        "hotfix_installed" = $SpeculationControl.KVAShadowWindowsSupportPresent
        "hotfix_enabled"   = $SpeculationControl.KVAShadowWindowsSupportEnabled
        "hardware_support" = $SpeculationControl.KVAShadowPcidEnabled
        "hardware_support_required" = $SpeculationControl.KVAShadowRequired
        "compliant"        = if (!$SpeculationControl.KVAShadowRequired -or ($SpeculationControl.KVAShadowRequired -and $SpeculationControl.KVAShadowWindowsSupportEnabled)) {$True} else {$False}
    })
}
$arrCVE | ConvertTo-Json