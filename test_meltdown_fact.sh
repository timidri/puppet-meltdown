#!/bin/bash
bundle install --path .bundle/gems/
bundle exec rake 'litmus:provision_list[vmpooler]'
bundle exec rake litmus:install_agent
bundle exec rake litmus:install_module
bundle exec rake litmus:acceptance:parallel
if [ $? == 0 ]; then
  bundle exec rake litmus:tear_down
fi