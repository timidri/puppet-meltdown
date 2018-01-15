# Class: meltdown::windows
# Ensures registry settings and OS patches are in place to mitigate against Spectre & Meltdown vulnerabilities
#
class meltdown::windows {
  # resources
  # These registry values are benign, won't do anything on systems that are not yet patched. So always install them.
  registry_value { 'SpeculativeExecutionProtection_FeatureSettingsOverride':
    ensure => present,
    path   => 'HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\FeatureSettingsOverride',
    type   => dword,
    data   => 0,
  }
  registry_value { 'SpeculativeExecutionProtection_FeatureSettingsOverrideMask':
    ensure => present,
    path   => 'HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\FeatureSettingsOverrideMask',
    type   => dword,
    data   => 3,
  }
  registry_key { 'SpeculativeExecutionProtection_HyperV_Parent':
    ensure => present,
    path   => 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Virtualization',
  }
  registry_value { 'SpeculativeExecutionProtection_HyperV':
    ensure  => present,
    path    => 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Virtualization\MinVmVersionForCpuBasedMitigations',
    type    => string,
    data    => '1.0',
    require => Registry_key['SpeculativeExecutionProtection_HyperV_Parent']
  }
}
