class Alert < ActiveRecord::Base
	belongs_to :action
	has_many :alert_args, :dependent => :destroy
	@@severities = {0 => 'none', 1000 => 'low', 2000 => 'medium', 3000 => 'high', 4000 => 'critical'}

	def san(val)
		ActionController::Base.helpers.sanitize(val).gsub("\\","\\<wbr>").gsub(",",",<wbr>")
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
end
