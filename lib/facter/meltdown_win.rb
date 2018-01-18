require 'json'

Facter.add('meltdown') do
  confine kernel: 'windows'
  setcode do
    sysroot = ENV['SystemRoot']
    programdata = ENV['ProgramData']
    powershell = "#{sysroot}\\system32\\WindowsPowerShell\\v1.0\\powershell.exe"
    checker_script = "#{programdata}\\PuppetLabs\\puppet\\cache\\lib\\meltdown\\spectre-meltdown-checker.ps1"
    JSON.parse(Facter::Util::Resolution.exec("#{powershell} -ExecutionPolicy Unrestricted -File #{checker_script}"))
  end
end
