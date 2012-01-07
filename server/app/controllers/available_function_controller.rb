class AvailableFunctionController < ApplicationController
	before_filter :login_required
	respond_to :json

	# GET /available_function/1.json
	def show
		func = AvailableFunction.find(params[:id])
		respond_with(:params => func.parameters.all(:order => 'num'),
				:decl => func.decl)
	end
end
