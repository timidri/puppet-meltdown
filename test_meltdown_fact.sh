#!/bin/bash
# usage: test_meltdown_fact [test|acceptance|travis]
# without arguments, scope is "test"
scope=${1:-"test"}
# install gems
bundle install
# provision nodes for testing scope
echo "Provisioning scope ${scope}..."
bundle exec rake "litmus:provision_list[${scope}]"
[ $scope == "travis" ] && bundle exec bolt task run package name=curl action=install --nodes all --modulepath=spec/fixtures/modules --inventory=./inventory.yaml
# install puppet agent on the nodes
echo "Installing agent..."
bundle exec rake litmus:install_agent
# install the meltdown module on the nodes
echo "Installing meltdown module..."
bundle exec rake litmus:install_module
# run the acceptance tests in parallel
echo "Running acceptance tests..."
bundle exec rake litmus:acceptance:parallel
if [ $? == 0 ]; then
  # tear down the nodes. Note: if the testing failed,
  # tear down is not done and needs to be done manually
  bundle exec rake litmus:tear_down
fi
