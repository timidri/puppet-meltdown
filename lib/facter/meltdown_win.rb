require 'json'

Facter.add('meltdown') do
  confine kernel: 'windows'
  setcode do
    sysroot = ENV['SystemRoot']
    powershell = "#{sysroot}\\system32\\WindowsPowerShell\\v1.0\\powershell.exe"
    # get the script path relative to facter Ruby program
    checker_script = File.join(
      File.expand_path(File.dirname(__FILE__)),
      '..',
      'meltdown',
      'spectre-meltdown-checker.ps1',
    )
    JSON.parse(Facter::Util::Resolution.exec("#{powershell} -ExecutionPolicy Unrestricted -File #{checker_script}"))
  end
end
