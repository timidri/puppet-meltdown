Facter.add('meltdown') do
  confine osfamily: 'windows'
  setcode do
    sysroot = ENV['SystemRoot']
    programdata = ENV['ProgramData']
    powershell = "#{sysroot}\\system32\\WindowsPowerShell\\v1.0\\powershell.exe"
    checker_script = "#{programdata}\\PuppetLabs\\puppet\\cache\\lib\\threats\\threats-checker.ps1"
    Facter::Util::Resolution.exec("#{powershell} -ExecutionPolicy Unrestricted -File #{checker_script}")
  end
end
