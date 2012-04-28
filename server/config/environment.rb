# Load the rails application
require File.expand_path('../application', __FILE__)

Rails.logger = Logger.new(STDOUT)

# Initialize the rails application
Ambush::Application.initialize!

require 'fileutils'

dir = File.join(File.dirname(__FILE__), '..', 'app', 'assets', 'sigs')
Dir.foreach(dir) do |f|
	if not f.end_with?('.key','.','.keep') then
		FileUtils.rm_f( File.join(dir,f) )
	end
end
