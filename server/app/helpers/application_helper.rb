module ApplicationHelper
	def browserclass
		@browser_name ||= begin
			ua = request.env['HTTP_USER_AGENT'].downcase
			if ua.index('msie') && !ua.index('opera') && !ua.index('webtv')
				msieindx = ua.index('msie')
				if ua[msieindx + 5,ua.index(';',msieindx)-msieindx-5].to_i < 10
					'earlyie'
				else
					'ie10'
				end
			elsif ua.index('gecko/') || ua.index('mozilla/')
				'gecko'
			elsif ua.index('applewebkit/')
				'webkit'
			end
		end
	end

	# turns a regex list from display format (multiline) to a lowercase regex
	# also null pads to 4 byte alignment
	def self.splitregex(str)
		return "\x00\x00\x00\x00".encode('binary') if str == nil or str.chomp == ''
		newstr = '(' + str.chomp.gsub(/\r\n/,'|').gsub(/\n/,'|') + ')'
		newstr = newstr.downcase.encode("UTF-16LE").force_encoding('binary')
		newstr = newstr + ("\x00" * (4 - (newstr.length % 4)))
	end
end
