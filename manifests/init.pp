# meltdown
#
# Includes os-specific prerequisites
#
# @summary Includes os-specific prerequisites
#
# @example
#   include meltdown
class meltdown {
  case $facts['kernel'] {
    'Linux':   { include ::meltdown::linux }
    'windows': { include ::meltdown::windows }
    default:   { fail("Operating system ${facts['kernel']} not supported by meltdown.") }
  }
}
