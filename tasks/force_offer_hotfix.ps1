If (!(Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\QualityCompat')) {
    New-Item -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\QualityCompat'
}
$result = New-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\QualityCompat' -Name 'cadca5fe-87d3-4b96-b7fb-a231484277cc' -Value 0 -PropertyType DWORD -Force
Write-Output 'Added registry entry to allow Spectre/Meltdown update to be offered to this system. This key should normally be set by your Antivirus vendor. Use at your own risk!'