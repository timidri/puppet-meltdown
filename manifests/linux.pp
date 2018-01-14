# meltdown::linux
# our meltdown detection requires the package `binutils` to be installed 

class meltdown::linux {
  package { 'binutils':
    ensure => installed,
  }
}
