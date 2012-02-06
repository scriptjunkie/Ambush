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
		if self.data and self.parameter.paramtype ==  1  # if integer
			# get 64 bit or 32 bit
			if self.data.length == 4
				number = self.data.unpack('V')[0] 
			else
				number = self.data.unpack('Q')[0]
			end
			# find an intelligent base to display in. 10 by default, unless number is a power of two or power of two - 1
			# or the argument is a bitmask type
			if number != 0 && (number & (number - 1) == 0 || number & (number + 1) == 0 ||
					self.alert.action.arguments.order('id').offset(self.parameter.num - 1).first.argtype == 6)
				return "0x#{number.to_s(16)}"
			else
				return number.to_s
			end
		end
		self.data.inspect
	end
end
