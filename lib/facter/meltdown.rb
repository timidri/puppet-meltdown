Facter.add('meltdown') do
    confine :kernel => :linux
    value = ""
    checker_script = ""
    setcode do
      require 'json'
      # get the script path relative to facter Ruby program
      checker_script = File.join(File.expand_path(File.dirname(__FILE__)), '..', 
        'meltdown', 'spectre-meltdown-checker.sh')
      value = Facter::Core::Execution.exec("/bin/sh #{checker_script} --batch json")
      value = JSON.pretty_generate(JSON(value))
    end
    value
end
