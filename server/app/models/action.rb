class Action < ActiveRecord::Base
	belongs_to :available_function
	belongs_to :signature_set
	has_many :arguments, :dependent => :destroy
	has_many :alerts, :dependent => :destroy
	@@actions = ['ALERT', 'BLOCK', 'KILLPROC', 'KILLTHREAD']

	def actionStr
		@@actions[self.action]
	end

	def arg_str
		arguments.map{ |arg| arg.to_s }.join(', ')
	end

	def setAction(actstr)
		self.action = @@actions.index(actstr)
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
