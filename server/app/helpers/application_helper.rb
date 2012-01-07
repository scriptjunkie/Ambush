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
end
