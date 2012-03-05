class AvailableFunction < ActiveRecord::Base
	belongs_to :available_dll
	has_many :parameters, :dependent => :destroy
	has_many :actions, :dependent => :destroy

	# Either get a function or create a new one if it is changed
	def self.find_or_create(funcname, funcparams, dll)
		newFunc = false
		func = AvailableFunction.where("decl IS NOT NULL").find(:first, :conditions => 
				{'available_dll_id' => dll.id, 'name' => funcname})

		#Check if we need to make a new one - if it wasn't found or params have changed
		paramtypes = ['?', 'integer', '?', 'c string', 'wide-char string', 'pointer', '?', 'blob']
		if func != nil
			parameters = func.parameters.all(:order => 'num')
			changed = parameters.length != funcparams.length
			funcparams.each_with_index do |fp, i|
				break if not fp.has_key? 'name' # standard function - no param info is provided
				
				if parameters[i] == nil or parameters[i].name != fp['name'] or 
						parameters[i].paramtype != paramtypes.index(fp['paramtype'])
					changed = true
					break
				end
			end
			return func if not changed # no need to continue if no change
		end
		
		#make a new func
		func = AvailableFunction.new(:name => funcname, :available_dll => dll)
		func.save

		#add params
		funcparams.each_with_index do |fp, i|
			p = Parameter.new(:name => ActionController::Base.helpers.strip_tags(fp['name']), 
					:num => i+1, :available_function => func)
			p.paramtype = paramtypes.index(fp['paramtype'])
			raise "Error - invalid parameter type; try one of these:\n#{fp.inspect}" if p.paramtype == nil

			if fp['type'] == 'Blob' #must give blob length
				p.arg = fp['blobval'] if fp['subtype'] == 'ARG'
				p.size = fp['blobval'] if fp['subtype'] == 'VAL'

				# simplified format uses 'size argument' or 'size'
				p.arg = fp['size argument'] if fp.has_key? 'size argument'
				p.size = fp['size'] if fp.has_key? 'size'
			end
			p.save
		end
		func
	end

	def compiled(ssid)
		#get actions
		ssid = SignatureSet.first.id if ssid == nil
		actions = Action.where(:available_function_id => self.id, :signature_set_id => ssid)
		return '' if actions.length == 0

		#setup name
		fname = self.name + ("\x00"*(4-(self.name.length % 4)))
		params = self.parameters.all(:order => 'num')
		out = [params.length, actions.length, fname.length].pack("V*") + fname
		actions.each do |action|
			out << action.compiled
		end
		params.each do |parameter|
			out << parameter.compiled
		end
		# size, numArgs, numActions, nameLen, name[], actions[], parameters[]
		[out.size+4].pack("V*") + out
	end
end
