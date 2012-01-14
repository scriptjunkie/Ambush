class SessionsController < ApplicationController
	protect_from_forgery
	def new
		@first_time = (User.count == 0)
	end

	def create
		if User.count == 0
			user = User.new(:username => params[:login], :password => params[:password])
			user.save
			redirect_to root_url, :notice => "Registration successful. Please log in."
			return
		end
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
