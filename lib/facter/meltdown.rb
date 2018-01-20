require 'json'

def convert_structure(json_array)
  output = {}
  json_array.each do |item|
    key = item['CVE']
    value = {
      CVE:          key.gsub(%r{CVE-}, ''),
      description:  item['NAME'],
      vulnerable:   item['VULNERABLE'],
      info: {
        hardware:   item['INFOS'],
      },
    }
    output[key] = value
  end
  output
end

# used for testing on a Mac
def json_stub
  value = <<-EOT
  [
    {
      "NAME": "SPECTRE VARIANT 1",
      "CVE": "CVE-2017-5753",
      "VULNERABLE": false,
      "INFOS": "106 opcodes found, which is >= 70, heuristic to be improved when official patches become available"
    },
    {
      "NAME": "SPECTRE VARIANT 2",
      "CVE": "CVE-2017-5715",
      "VULNERABLE": true,
      "INFOS": "IBRS hardware + kernel support OR kernel with retpoline are needed to mitigate the vulnerability"
    },
    {
      "NAME": "MELTDOWN",
      "CVE": "CVE-2017-5754",
      "VULNERABLE": false,
      "INFOS": "PTI mitigates the vulnerability"
    }
  ]
  EOT
  value
end

Facter.add('meltdown') do
  confine :virtual do |virtual|
    virtual != 'docker'
  end
  confine :kernel do |kernel|
    kernel == 'darwin' || kernel == 'linux'
  end
  value = ''
  checker_script = ''
  setcode do
    if Facter.value(:osfamily) == 'Darwin'
      # just generate some output for testing
      value = JSON.parse(json_stub)
    else
      # get the script path relative to facter Ruby program
      checker_script = File.join(
        File.expand_path(File.dirname(__FILE__)),
        '..',
        'meltdown',
        'spectre-meltdown-checker.sh',
      )
      value = JSON.parse(Facter::Core::Execution.exec("/bin/sh #{checker_script} --batch json"))
    end
    convert_structure(value)
  end
end
