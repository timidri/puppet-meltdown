# frozen_string_literal: true

require 'spec_helper_acceptance'
require 'json'

def valid_json?(json)
  JSON.parse(json)
rescue JSON::ParserError
  false
end

RSpec::Matchers.define :be_valid_json do
  match do |json|
    valid_json?(json.strip)
  end
end

describe "testing meltdown fact on #{os[:family]}" do
  facter_path = 'production/modules/meltdown/lib/facter'
  facter_command = 'facter -p --json meltdown'
  command = if os[:family] == 'windows'
              "$env:FACTERLIB=\"$(puppet config print environmentpath)/#{facter_path}\"; #{facter_command}"
            else
              "FACTERLIB=$(puppet config print environmentpath)/#{facter_path} #{facter_command}"
            end
  result = run_shell(command)
  describe result do
    its(:exit_code) { is_expected.to eq 0 }
    its(:stdout) { is_expected.to be_valid_json }
    its(:stdout) { is_expected.to contain 'CVE-2017-5753' }
  end
end
