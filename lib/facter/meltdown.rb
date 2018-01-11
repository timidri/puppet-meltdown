Facter.add('meltdown') do
    # confine :kernel => :linux
    value = ""
    checker_script = ""
    setcode do
      require 'json'
    #    value = Facter::Core::Execution.exec('/var/tmp/spectre-meltdown-check --batch json')
      checker_script = "/opt/puppetlabs/puppet/cache/lib/spectre-meltdown-checker.sh"
      value = Facter::Core::Execution.exec("/bin/sh #{checker_script} --batch json")
      value = JSON.pretty_generate(JSON(value))
    end
    value
end
