Facter.add('meltdown') do
    confine :kernel => :Linux
    value = ""
    checker_script = ""
    setcode do
      require 'json'
      checker_script = "/opt/puppetlabs/puppet/cache/lib/spectre-meltdown-checker.sh"
      value = Facter::Core::Execution.exec("/bin/sh #{checker_script} --batch json")
      value = JSON.pretty_generate(JSON(value))
    end
    value
end
