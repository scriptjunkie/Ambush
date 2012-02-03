class AlertArg < ActiveRecord::Base
	belongs_to :parameter
	belongs_to :alert

	def initialize (alert, message, param)
		super(:alert => alert)
		size = message.slice!(0, 4).unpack('V')[0]
		type = message.slice!(0, 4).unpack('V')[0]
		self.data = message.slice!(0, size - 8)
		self.data = self.data.force_encoding("UTF-16LE").encode('UTF-8') if param.paramtype == 4
		self.parameter = param
		self.save
	end

	def display
		return self.data.unpack('V')[0].to_s if self.data and self.parameter.paramtype ==  1
		self.data.inspect
	end
end
