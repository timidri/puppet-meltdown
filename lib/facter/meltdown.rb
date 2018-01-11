Facter.add('meltdown') do
    # confine :kernel => :linux
    value = ""
    setcode do
    #    value = Facter::Core::Execution.exec('/var/tmp/spectre-meltdown-check --batch json')
    value = <<-HEREDOC
    [
        {
          CVE => "CVE-2017-5753",
          INFOS => "106 opcodes found, which is >= 70, heuristic to be improved when official patches become available",
          NAME => "SPECTRE VARIANT 1",
          VULNERABLE => false
        },
        {
          CVE => "CVE-2017-5715",
          INFOS => "IBRS hardware + kernel support OR kernel with retpoline are needed to mitigate the vulnerability",
          NAME => "SPECTRE VARIANT 2",
          VULNERABLE => true
        },
        {
          CVE => "CVE-2017-5754",
          INFOS => "PTI mitigates the vulnerability",
          NAME => "MELTDOWN",
          VULNERABLE => false
        }
      ]"
    HEREDOC

    end
    value
end
