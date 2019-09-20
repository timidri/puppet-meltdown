#!/bin/bash
# usage: test_meltdown_fact [test|acceptance]
# without arguments, scope is "test"
scope=${1:-"test"}
# install gems
bundle install --path .bundle/gems/
# provision nodes for testing scope
bundle exec rake "litmus:provision_list[${scope}]"
# install puppet agent on the nodes
bundle exec rake litmus:install_agent
# install the meltdown module on the nodes
bundle exec rake litmus:install_module
# run the acceptance tests in parallel
bundle exec rake litmus:acceptance:parallel
if [ $? == 0 ]; then
  # tear down the nodes. Note: if the testing failed,
  # tear down is not done and needs to be done manually
  bundle exec rake litmus:tear_down
fi
