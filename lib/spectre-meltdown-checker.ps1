$arrCVE = @{}
switch -Wildcard ((Get-WmiObject -class Win32_OperatingSystem).Caption) {
    'Microsoft Windows Server 2008 R2*'       { $hotfix = 'KB4056897' }
    'Microsoft Windows Server 2012 R2*'       { $hotfix = 'KB4056898' }
    'Microsoft Windows Server 2016*'          { $hotfix = 'KB4056890' }
    'Microsoft Windows Server, version 1709*' { $hotfix = 'KB4056892' }
}
if ($hotfix) {
    $arrCVE.Add('CVE-2017-5715', [bool](Get-WmiObject -query 'select * from win32_quickfixengineering' | ? HotFixID -eq $hotfix))
    $arrCVE.Add('CVE-2017-5753', [bool](Get-WmiObject -query 'select * from win32_quickfixengineering' | ? HotFixID -eq $hotfix))
    $arrCVE.Add('CVE-2017-5754', [bool](Get-WmiObject -query 'select * from win32_quickfixengineering' | ? HotFixID -eq $hotfix))
}
$arrCVE | ConvertTo-Json
