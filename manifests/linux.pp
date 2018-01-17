# meltdown::linux
# Installs the pre-requisites for the meltdown detection script

class meltdown::linux {
  ensure_packages('binutils')
}
