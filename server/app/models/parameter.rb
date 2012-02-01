class Parameter < ActiveRecord::Base
	@@types = ['Ignore', 'Integer', 'Range', 'C string', 'WC string', 'Pointer', 'Bitmask', 'Blob', 'Not']
	belongs_to :available_function

	def compiled
		raise "Error - invalid parameter type" if self.paramtype == nil
		out = [self.paramtype].pack("V*")
		case @@types[self.paramtype]
		when 'Ignore'
		when 'Integer', 'Not', 'C string', 'WC string'
			out << [0].pack("V*")
		when 'Range', 'Pointer', 'Bitmask'
			out << [0, 0].pack("V*")
		when 'Blob'
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
