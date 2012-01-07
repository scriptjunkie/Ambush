class AlertArg < ActiveRecord::Base
	belongs_to :parameter
	belongs_to :alert

	def parse (message, param)
		size = message.slice!(0, 4).unpack('V')[0]
		type = message.slice!(0, 4).unpack('V')[0]
		self.data = message.slice!(0, size - 8)
		self.parameter = param
	end

	def display
		return self.data.unpack('V')[0].to_s if self.data and self.parameter.paramtype ==  1
		self.data.inspect
	end
end
