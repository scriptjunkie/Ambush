class AvailableDllController < ApplicationController
	before_filter :login_required
	respond_to :json

  # GET /available_dll/show.json?name=
	def show
		respond_with(AvailableFunction.find(:all, 
			:include => [:available_dll], 
			:conditions => ['available_dlls.name = ? and available_functions.decl IS NOT NULL', params[:name]],
			:order => "available_functions.name").map{ |f| [f.id,f.name] })
	end
end
