class Alert < ActiveRecord::Base
	belongs_to :action
	has_many :alert_args, :dependent => :destroy

	def san(val)
		ActionController::Base.helpers.sanitize(val).gsub("\\","\\<wbr>").gsub(",",",<wbr>")
	end

	def row(new)
		rowclass = ''
		rowclass = ' class="new"' if new
		"<tr id=\"a#{self.id}\"#{rowclass}><th scope=\"row\">#{san(self.action.name) }</th><td>#{self.created_at } #{self.updated_at if self.count > 1 and self.updated_at - self.created_at > 5 }</td><td>#{self.action.severity }</td><td>#{san(self.action.actionStr) }</td><td>#{san(self.user) }</td><td>#{san(self.computer) } (#{self.ip })</td><td>#{san(self.process) } (#{self.pid })</td><td>#{san(self.module)}</td><td>#{san(self.action.available_function.available_dll.name) }</td><td>#{san(self.action.available_function.name+'('+self.alert_args.map { |aa| aa.display }.join(","))})</td><td>#{self.count}</td></tr>"
	end
end
