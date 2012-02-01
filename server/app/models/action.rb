class Action < ActiveRecord::Base
	belongs_to :available_function
	belongs_to :signature_set
	has_many :arguments, :dependent => :destroy
	has_many :alerts, :dependent => :destroy
	@@actions = ['ALERT', 'BLOCK', 'KILLPROC', 'KILLTHREAD']
	@@memconstants = {0x10 => 'PAGE_EXECUTE', 0x20 => 'PAGE_EXECUTE_READ', 
			0x40 => 'PAGE_EXECUTE_READWRITE', 0x80 => 'PAGE_EXECUTE_WRITECOPY', 
			0x1 => 'PAGE_NOACCESS', 0x2 => 'PAGE_READONLY', 
			0x4 => 'PAGE_READWRITE', 0x8 => 'PAGE_WRITECOPY'}
	@@memmodes = {'PAGE_EXECUTE' => 0x10, 'PAGE_EXECUTE_READ' => 0x20, 
			'PAGE_EXECUTE_READWRITE' => 0x40, 'PAGE_EXECUTE_WRITECOPY' => 0x80, 
			'PAGE_NOACCESS' => 0x1, 'PAGE_READONLY' => 0x2, 
			'PAGE_READWRITE' => 0x4, 'PAGE_WRITECOPY' => 0x8}

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
		simple = {'name' => self.name, 'action' => @@actions[self.action], 'severity' => self.severity, 
				'function' => self.available_function.name, 'dll' => self.available_function.available_dll.name, 
				'arguments' => self.arguments.map{|a| a.simplified(defined)} }
		simple['retval'] = self.retval if self.action == 1
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
		act = Action.new(:action => @@actions.index(simple['action']), :available_function_id => func.id,
				:severity => simple['severity'], :name => simple['name'], :signature_set_id => set.id)

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
		args = self.arguments
		raise 'Error - no args' if args.length == 0
		# default processName - ''
		self.exepath = '' if self.exepath == nil
		name = self.exepath + ("\x00"*(4-(self.exepath.length % 4)))
		# put together output
		out = [self.id, self.action, self.severity, self.retval, self.actiontype, args.length,
				name.length].pack("VVVQVVV")
		# default retAddress - {}
		if self.retprotectType == nil
			out << [0,0].pack('V*')
		else
			raise "Error - invalid argument type for retAddress" if self.retprotectMode == nil
			out << [self.retprotectType, self.retprotectMode].pack("V*")
		end
		# arguments - required
		out << name
		args.each do |arg|
			out << arg.compiled
		end
		# size, id, action, severity, retval, type, numargs, exePathLen, retprotectType, retprotectMode, exePath[], args[]
		[out.size + 4].pack("V*") + out
	end
end
