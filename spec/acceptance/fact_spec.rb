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
  result = run_shell('puppet facts')
  describe result do
    its(:exit_code) { is_expected.to eq 0 }
    its(:stdout) { is_expected.to be_valid_json }
  end
  facts = JSON.parse(result[:stdout])['values']
  describe facts do
    it { is_expected.to include 'meltdown' }
    it { expect(facts['meltdown']).to include 'CVE-2017-5753' }
  end
end
