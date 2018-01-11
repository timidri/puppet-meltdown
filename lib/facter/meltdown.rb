Facter.add('meltdown') do
    # confine :kernel => :linux
    value = ""
    checker_script = ""
    setcode do
    #    value = Facter::Core::Execution.exec('/var/tmp/spectre-meltdown-check --batch json')
      checker_script = File.read("/opt/puppetlabs/puppet/cache/lib/spectre-meltdown-checker.sh")
      value =  system(checker_script, "--batch json")
    end
    value
end
