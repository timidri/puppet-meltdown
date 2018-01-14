# meltdown::linux
# Installs the pre-requisites for the meltdown detection script

class meltdown::linux {
  package { 'binutils':
    ensure => installed,
  }
}
