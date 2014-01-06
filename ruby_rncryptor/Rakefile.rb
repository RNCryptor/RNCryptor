require 'rubygems'
require 'rspec/core/rake_task'
require 'rake'

task :default => :spec
RSpec::Core::RakeTask.new(:spec)