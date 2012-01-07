class AvailableFunction < ActiveRecord::Base
	belongs_to :available_dll
	has_many :parameters, :dependent => :destroy
	has_many :actions, :dependent => :destroy

	def compiled(ssid)
		#get actions
		ssid = SignatureSet.first.id if ssid == nil
		actions = Action.where(:available_function_id => self.id, :signature_set_id => ssid)
		return '' if actions.length == 0

		#setup name
		fname = self.name + ("\x00"*(4-(self.name.length % 4)))
		params = self.parameters.all(:order => 'num')
		acts = self.actions.all
		out = [params.length, acts.length, fname.length].pack("V*") + fname
		acts.each do |action|
			out << action.compiled
		end
		params.each do |parameter|
			out << parameter.compiled
		end
		# size, numArgs, numActions, nameLen, name[], actions[], parameters[]
		[out.size+4].pack("V*") + out
	end
end
