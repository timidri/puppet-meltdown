require 'spec_helper_acceptance'
require 'json'

def valid_json?(json)
  JSON.parse(json)
  return true
rescue JSON::ParserError => e
  return false
end

RSpec::Matchers.define :be_valid_json do
  match do |json|
    valid_json?(json.strip)
  end
end

describe "testing meltdown fact on #{os[:family]}" do
  facter_path = "production/modules/meltdown/lib/facter"
  facter_command = 'facter -p --json meltdown'
  if os[:family] == 'windows'
    command = "$env:FACTERLIB=\"$(puppet config print environmentpath)/#{facter_path}\"; #{facter_command}"
  else
    command = "FACTERLIB=$(puppet config print environmentpath)/#{facter_path} #{facter_command}"
  end
  # puts command
  result = run_shell(command)
  describe result do
    its(:exit_code) { should eq 0 }
    its(:stdout) { should be_valid_json }
    its(:stdout) { should contain 'CVE-2017-5753' }
  end
end
