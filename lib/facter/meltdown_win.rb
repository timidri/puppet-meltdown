Facter.add('meltdown') do
    confine :osfamily => :windows
    setcode do
        sysroot = ENV['SystemRoot']
        programdata = ENV['ProgramData']
        powershell = "C:\\Windows\\system32\\WindowsPowerShell\\v1.0\\powershell.exe"
        checker_script = "C:\\ProgramData\\PuppetLabs\\puppet\\cache\\lib\\spectre-meltdown-checker.ps1"
        Facter::Util::Resolution.execute("#{powershell} -ExecutionPolicy Unrestricted -File #{checker_script}")
    end
end
