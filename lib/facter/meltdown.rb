Facter.add('meltdown') do
    # confine :kernel => :linux
    value = ""
    checker_script = ""
    setcode do
      require 'json'
      # get the script path relative to facter Ruby program
      checker_script = File.join(File.expand_path(File.dirname(__FILE__)), '..', 
        'meltdown', 'spectre-meltdown-checker.sh')
      value = JSON(Facter::Core::Execution.exec("/bin/sh #{checker_script} --batch json"))
      # value = <<-EOT
      # [
      #   {
      #     "NAME": "SPECTRE VARIANT 1",
      #     "CVE": "CVE-2017-5753",
      #     "VULNERABLE": false,
      #     "INFOS": "106 opcodes found, which is >= 70, heuristic to be improved when official patches become available"
      #   },
      #   {
      #     "NAME": "SPECTRE VARIANT 2",
      #     "CVE": "CVE-2017-5715",
      #     "VULNERABLE": true,
      #     "INFOS": "IBRS hardware + kernel support OR kernel with retpoline are needed to mitigate the vulnerability"
      #   },
      #   {
      #     "NAME": "MELTDOWN",
      #     "CVE": "CVE-2017-5754",
      #     "VULNERABLE": false,
      #     "INFOS": "PTI mitigates the vulnerability"
      #   }
      # ]
      # EOT

      value.each do | item |
        # puts item["CVE"]
        # puts item["VULNERABLE"]
        Facter.add(item["CVE"]) do
          setcode do
            item["VULNERABLE"]
          end
        end
      end
    end
    value
    # JSON.pretty_generate(value)
end
