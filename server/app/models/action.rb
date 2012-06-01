class Action < ActiveRecord::Base
	belongs_to :available_function
	belongs_to :signature_set
	has_many :arguments, :dependent => :destroy
	has_many :alerts, :dependent => :destroy
	@@actions = ['alert', 'block', 'kill process', 'kill thread']
	@@memconstants = {0x10 => 'PAGE_EXECUTE', 0x20 => 'PAGE_EXECUTE_READ', 
			0x40 => 'PAGE_EXECUTE_READWRITE', 0x80 => 'PAGE_EXECUTE_WRITECOPY', 
			0x1 => 'PAGE_NOACCESS', 0x2 => 'PAGE_READONLY', 
			0x4 => 'PAGE_READWRITE', 0x8 => 'PAGE_WRITECOPY'}
	@@memmodes = {'PAGE_EXECUTE' => 0x10, 'PAGE_EXECUTE_READ' => 0x20, 
			'PAGE_EXECUTE_READWRITE' => 0x40, 'PAGE_EXECUTE_WRITECOPY' => 0x80, 
			'PAGE_NOACCESS' => 0x1, 'PAGE_READONLY' => 0x2, 
			'PAGE_READWRITE' => 0x4, 'PAGE_WRITECOPY' => 0x8}
	@@severityConstants = {0 => 'none', 1000 => 'low', 2000 => 'medium', 3000 => 'high', 4000 => 'critical'}
	@@severityStrings = {'none' => 0, 'low' => 1000, 'medium' => 2000, 'high' => 3000, 'critical' => 4000}

	def actionStr
		@@actions[self.action]
	end

	def arg_str
		arguments.map{ |arg| arg.to_s }.join(', ')
	end

	def setAction(actstr)
		self.action = @@actions.index(actstr)
	end

	def simplified
		defined = self.available_function.decl != nil
		simple = {'name' => self.name, 'action' => @@actions[self.action],  
				'function' => self.available_function.name, 'dll' => self.available_function.available_dll.name, 
				'arguments' => self.arguments.map{|a| a.simplified(defined)} }
		simple['modblacklist'] = self.modblacklist if self.modblacklist != nil and self.modblacklist.length > 0
		simple['modwhitelist'] = self.modwhitelist if self.modwhitelist != nil and self.modwhitelist.length > 0
		simple['procblacklist'] = self.procblacklist if self.procblacklist != nil and self.procblacklist.length > 0
		simple['procwhitelist'] = self.procwhitelist if self.procwhitelist != nil and self.procwhitelist.length > 0
		simple['retval'] = self.retval if self.action == 1
		if @@severityConstants.has_key? self.severity
			simple['severity'] = @@severityConstants[self.severity]
		else
			simple['severity'] = self.severity
		end
		if self.retprotectMode != 0
			if @@memconstants.has_key? self.retprotectMode
				simple['retprotectMode'] = @@memconstants[self.retprotectMode]
			else
				simple['retprotectMode'] = self.retprotectMode
			end
		end
		simple
	end

	def self.from_simplified(simple, set)
		#Get or create DLL
		dll = AvailableDll.find_or_create(simple['dll'])

		#Get or create function
		func = AvailableFunction.find_or_create(simple['function'], simple['arguments'], dll)

		#Create action
		act = Action.new(:action => @@actions.index(simple['action'].downcase), :available_function_id => func.id,
				:name => simple['name'], :signature_set_id => set.id,
				:modblacklist => simple['modblacklist'], :modwhitelist => simple['modwhitelist'], 
				:procblacklist => simple['procblacklist'], :procwhitelist => simple['procwhitelist'])
		act.retval = simple['retval'] || 0

		#Severity
		if @@severityStrings.has_key? simple['severity'].downcase
			act.severity = @@severityStrings[simple['severity'].downcase]
		else
			act.severity = simple['severity'].to_i
		end

		#Return address conditions
		if simple['retprotectMode']
			memmode = @@memmodes[simple['retprotectMode']]
			memmode = simple['retprotectMode'].to_i if memmode == nil
			act.retprotectMode = memmode
		else
			act.retprotectMode = 0
		end
		act.retprotectType = 0
		act.save

		#Create args
		parameters = func.parameters.all(:order => 'num')
		simple['arguments'].each_with_index do |simplearg, index|
			Argument.from_simplified(simplearg, parameters[index], act)
		end
		#we changed the sig set
		act.signature_set.markchanged
	end

	# turns a regex list from display format (multiline) to a lowercase regex
	# also null pads to 4 byte alignment
	def splitregex(str)
		return "\x00\x00\x00\x00".encode('binary') if str == nil or str.chomp == ''
		newstr = '(' + str.chomp.gsub(/\r\n/,'|').gsub(/\n/,'|') + ')'
		newstr = newstr.downcase.encode("UTF-16LE").force_encoding('binary')
		newstr = newstr + ("\x00" * (4 - (newstr.length % 4)))
	end

	def compiled
		# action - required
		raise 'Error - must define an action' if self.action == nil
		# default type (PRE/POST) is PRE
		self.actiontype = 0 if self.actiontype == nil
		# default severity - Medium
		self.severity = 2000 if self.severity == nil
		# default retval - 0
		self.retval = 0 if self.retval == nil
		# args - required
		args = self.arguments.order('id')
		raise 'Error - no args' if args.length == 0
		# executable path black/white lists
		exeblack = splitregex(self.procblacklist)
		exewhite = splitregex(self.procwhitelist)
		# module black/white lists
		modblack = splitregex(self.modblacklist)
		modwhite = splitregex(self.modwhitelist)
		# put together output
		out = [self.id, self.action, self.severity, self.retval, self.actiontype, args.length,
				exeblack.length, exewhite.length, modblack.length, modwhite.length].pack("VVVQVVVVVV")
		# default retAddress - {}
		if self.retprotectMode == nil
			out << [0,0].pack('V*')
		else
			out << [self.retprotectType, self.retprotectMode].pack("V*")
		end
		# white/black lists
		out << exeblack + exewhite + modblack + modwhite
		# arguments
		args.each do |arg|
			out << arg.compiled
		end
		# size, id, action, severity, retval, type, numargs, exePathLen, retprotectType, retprotectMode, modPathLen, exePath[], modPath[], args[]
		[out.size + 4].pack("V*") + out
	end
end
