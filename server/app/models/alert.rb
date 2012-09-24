class Alert < ActiveRecord::Base
	belongs_to :action
	has_many :alert_args, :dependent => :destroy
	@@severities = {0 => 'none', 1000 => 'low', 2000 => 'medium', 3000 => 'high', 4000 => 'critical'}

	def san(val)
		ActionController::Base.helpers.sanitize(val).to_s.gsub("\\","\\<wbr>").gsub(",",",<wbr>")
	end

	def display
		self.alert_args.map { |aa| aa.display }.join(",")
	end

	def row(new)
		rowclass = ''
		rowclass = ' class="new"' if new
		severityStr = @@severities[self.action.severity] || self.action.severity.to_s
		"<tr id=\"a#{self.id}\"#{rowclass}><th scope=\"row\">#{san(self.action.name) }</th><td>#{self.created_at } #{self.updated_at if self.count > 1 and self.updated_at - self.created_at > 5 }</td><td>#{severityStr}</td><td>#{san(self.action.actionStr) }</td><td>#{san(self.user) }</td><td>#{san(self.computer) } (#{self.ip })</td><td>#{san(self.process) } (#{self.pid })</td><td>#{san(self.module)}</td><td>#{san(self.action.available_function.available_dll.name) }</td><td>#{san(self.action.available_function.name+'('+self.display)})</td><td>#{self.count}</td></tr>"
	end

	#formats according to a VISUAL element in syslog - minus quotes, :, =, and ]
	def cleanSyslog(str)
		newstr = ''
		str.each_char do |c|
			cval = c.ord
			newstr << c if cval >= 35 and cval <= 126 and cval != 58 and cval != 61 and cval != 93
		end
		newstr
	end

	def toSyslog
		dllname = self.action.available_function.available_dll.name

		#version 1; facility 699; severity scaled, rounded, and reversed to 0-7 integer range
		message = "1 699 " + (7 - [[0,self.action.severity].max, 3999].min / 4000.0 * 8).floor.to_s

		#rfc 3339 time format; hostname; sender name; sender inst
		message << " #{self.updated_at.strftime('%FT%T')} #{cleanSyslog(self.computer)} ambush - "

		#message, with unfiltered string values, in JSON
		message + ActiveSupport::JSON.encode({:computer => self.computer, :count => self.count, 
					:ip => self.ip, :module => self.module, :pid => self.pid, :process => self.process, :user => self.user, 
					:name => self.action.name, :signature_set => self.action.signature_set_id, :created_at => self.created_at, 
					:updated_at => self.updated_at, :severity => self.action.severity, 
					:dll => dllname, :function => self.action.available_function.name, 
					:args => self.display})
	end
end
