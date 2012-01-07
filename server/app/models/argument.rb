class Argument < ActiveRecord::Base
	belongs_to :action
	@@types = ['Ignore', '=', 'Range', 'C string', 'WC string', 'MEM', 'Bitmask', 'BLOB', 'Not']

	def to_s
		begin
			typestr = @@types[self.argtype].dup
			case typestr
			when '='
				typestr << " #{self.val1.to_s}"
			when 'Not'
				typestr << " #{self.val1.to_s}"
			when 'Range'
				typestr << " #{self.val1.to_s}-#{self.val2.to_s}"
			when 'Bitmask'
				typestr << " {#{['ANY','ALL','EXACT','NONE'][self.val1]} 0x#{self.val2.to_s(16)}}"
			when 'C string'
				typestr << " #{self.regExp}"
			when 'WC string'
				typestr << " #{self.regExp}"
			when 'MEM'
				typestr << " #{['ANY','ALL','EXACT','NONE'][self.val1]} 0x#{self.val2.to_s(16)}"
			end
			typestr
		rescue
			''
		end
	end

	def setval1(str)
		if str[0..1] == '0x'
			self.val1 = str[2..-1].to_i(16)
		else
			self.val1 = str.to_i
		end
	end

	def setval2(str)
		if String === str and str[0..1] == '0x'
			self.val2 = str[2..-1].to_i(16)
		else
			self.val2 = str.to_i
		end
	end

	def compiled
		out = [self.argtype].pack("V")
		case @@types[self.argtype]
		when 'Ignore'
		when '='
			raise 'Error - invalid DWORD' if self.val1 == nil
			out << [self.val1].pack("Q")
		when 'Not'
			raise 'Error - invalid DWORD' if self.val1 == nil
			out << [self.val1].pack("Q")
		when 'Range'
			raise 'Error - invalid DWORD range' if self.val1 == nil or self.val2 == nil
			out << [self.val1, self.val2].pack("QQ")
		when 'C string'
			raise 'Error - invalid C string' if self.regExp == nil
			stringVal = self.regExp+("\x00"*(4-(self.regExp.length % 4)))
			out << [stringVal.length].pack("V*") + stringVal
		when 'WC string'
			raise 'Error - invalid wide char string' if self.regExp == nil
			binaryVal = (self.regExp + "\x00").encode("UTF-16LE").force_encoding('binary')
			stringVal = binaryVal + ("\x00" * (4 - (self.regExp.length % 4)))
			out << [stringVal.length].pack("V*") + stringVal
		when 'MEM'
			self.val1 = 0 if self.val1 == nil
			raise "Error - invalid argument type for MEM mode argument" if self.val2 == nil
			out << [self.val1, self.val2].pack("V*")
		when 'Bitmask'
			self.val1 = 0 if self.val1 == nil
			raise "Error - invalid argument type for BITMASK mask argument" if self.val2 == nil
			out << [self.val1, self.val2].pack("VQ")
		when 'BLOB'
			if (self.val1 == -1 and self.val2 == 0) or self.val1 == nil or self.val2 == nil #insufficient info
				out = [0].pack("V") # ignore
			else
				# if not a number, must be a ref
				self.val1 = -1 if self.val1 == nil
				self.val2 = 0 if self.val2 == nil
				stringVal = self.regExp+("\x00"*(4-(self.regExp.length % 4)))
				out << [self.val1, self.val2, stringVal.length].pack("V*") + stringVal
			end
		else
			raise "Error - type #{self.argtype} not supported"
		end
		# size, type, value
		[out.size + 4].pack("V*") + out
	end
end
