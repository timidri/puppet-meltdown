#__FILE__
# => "how-to-get-the-directory-of-the-current-file-using-ruby.rb"

# File.dirname(__FILE__)
# => "."

# File.expand_path(File.dirname(__FILE__))
# => "/Users/dev/Documents/Github/Gists/awesome/"



# example:
puts __FILE__
puts File.dirname(__FILE__)
puts File.expand_path(File.dirname(__FILE__))

relpath = File.join(File.expand_path(File.dirname(__FILE__)), '..', 'foobar.sh')
puts relpath

# results: (from command line with this file)
# $ ruby how-to-get-the-directory-of-the-current-file-ruby.rb
# how-to-get-the-directory-of-the-current-file-using-ruby.rb
# .
# /Users/dev/Documents/Github/Gists/awesome/



# the following quoted from https://www.ruby-forum.com/topic/143383
#
# Phillip Gawlowski wrote:
# > On 02.01.2010 03:33, Kimball Johnson wrote:
# >> As to getting the parent directory of a file, try this:
# >>
# >> File.dirname(File.dirname(__FILE__))
# >>
# >> or for the absoluter path:
# >>
# >> File.expand_path(File.dirname(File.dirname(__FILE__)))
# >>
# >> dumb but smart?
# >
# > require "futils"
# > puts Dir.pwd
# 
# Note 1: the process's current working directory is in general unrelated
# to the directory where the script itself is located.
# 
# Note 2: you don't need to load any library to get access to Dir.pwd
