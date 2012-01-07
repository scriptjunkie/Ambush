class Parameter < ActiveRecord::Base
	@@types = ['DONTCARE', 'DWORD', 'DWORDRANGE', 'CSTRING', 'WCSTRING', 'MEM', 'BITMASK', 'BLOB']
	belongs_to :available_function

	def compiled
		raise "Error - invalid parameter type" if self.paramtype == nil
		out = [self.paramtype].pack("V*")
		case @@types[self.paramtype]
		when 'DONTCARE'
		when 'DWORD'
			out << [0].pack("V*")
		when 'DWORDRANGE'
			out << [0,0].pack("V*")
		when 'CSTRING'
			out << [0].pack("V*")
		when 'WCSTRING'
			out << [0].pack("V*")
		when 'MEM'
			out << [0, 0].pack("V*")
		when 'BITMASK'
			out << [0, 0].pack("V*")
		when 'BLOB'
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
