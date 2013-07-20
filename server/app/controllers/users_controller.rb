class UsersController < ApplicationController
	before_filter :login_required

	# GET /users
	# GET /users.json
	def index
		@users = User.all
		respond_to do |format|
			format.html # index.html.erb
			format.json { 
				render json: @users
			}
		end
	end

	# DELETE /users/1.json
	def destroy
		user = User.find(params[:id])
		user.destroy
		send_data ''
	end

	# POST /users
	# POST /users.json
	def create
		#Changing password
		if(params[:user][:id])
			user = User.find(params[:user][:id])
			user.password = params[:user][:password]
			user.save!
			send_data ''
			return
		end
		#New user
		founduser = User.find_by_username(params[:user][:username])
		if(founduser)
			render :status => :forbidden, :text => "Not allowed to overwrite user"
		else
			user = User.new(params[:user])
			user.save
			send_data ''
		end
	end
end
