class AvailableDll < ActiveRecord::Base
	has_many :available_functions, :dependent => :destroy

	def self.find_or_create(name)
		dll = AvailableDll.find(:first, :conditions => {:name => name})
		if dll == nil
			dll = AvailableDll.new(:name => name)
			dll.save
		end
		dll
	end

	def compiled(ssid)
		dname = self.name.downcase + ("\x00"*(4-(self.name.length % 4)))
		funcs = self.available_functions.joins(:actions).where('actions.signature_set_id' => ssid)
		numfuncs = 0
		temp = ''
		funcs.each do |func|
			funcompiled = func.compiled(ssid)
			if(funcompiled.length > 0)
				temp << funcompiled
				numfuncs += 1
			end
		end
		return '' if numfuncs == 0
		out = [numfuncs, dname.length].pack("V*") + dname + temp
		# size, numfuncs, namelen, name[], funcs[]
		[out.size + 4].pack("V*") + out
	end
end
