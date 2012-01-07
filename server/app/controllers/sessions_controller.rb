class SessionsController < ApplicationController
	protect_from_forgery
	def new
	end

	def create
		user = User.authenticate(params[:login], params[:password])
		if user
			session[:user_id] = user.id
			redirect_to root_url, :notice => "Logged in successfully."
		else
			flash.now[:alert] = "Invalid login or password."
			render :action => 'new'
		end
	end

	def destroy
		session[:user_id] = nil
		redirect_to root_url, :notice => "You have been logged out."
	end
end
