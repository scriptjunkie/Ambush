class Parameter < ActiveRecord::Base
	@@types = ['ignore', 'integer', 'range', 'c string', 'wide-char string', 'pointer', 'bitmask', 'blob', 'not']
	belongs_to :available_function

	def compiled
		raise "Error - invalid parameter type" if self.paramtype == nil
		out = [self.paramtype].pack("V*")
		case @@types[self.paramtype]
		when 'ignore'
		when 'integer', 'not', 'c string', 'wide-char string'
			out << [0].pack("V*")
		when 'range', 'pointer', 'bitmask'
			out << [0, 0].pack("V*")
		when 'blob'
			Rails.logger.debug self.inspect
			# if not a number, must be a ref
			self.arg = -1 if self.arg == nil
			self.size = 0 if self.size == nil
			out << [self.arg, self.size, 0].pack("V*")
		else
			raise "Error - type #{self.paramtype} not supported"
		end
		# size, type, value
		[out.size + 4].pack("V*") + out
	end
end
