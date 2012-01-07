class AlertsController < ApplicationController
	protect_from_forgery
	before_filter :login_required, :except => :create

	# GET /signature_sets
	# GET /signature_sets.json
	def index
		@alerts = Alert.all

		respond_to do |format|
			format.html # index.html.erb
			format.json { render json: @alerts }
		end
	end

	# GET /alerts/1
	# GET /alerts/1.json
	def show
		@alert = Alert.find(params[:id])

		respond_to do |format|
			format.html # show.html.erb
			format.json { render json: @alert }
		end
	end

	# GET /alerts/clear
	def clear
		Alert.destroy_all
		respond_to do |format|
				format.html { redirect_to '/alerts', notice: 'Alerts have been cleared.' }
				format.json { redirect_to '/alerts', notice: 'Alerts have been cleared.' }
		end
	end

	# POST /alerts
	# POST /alerts.json
	def create
		#put together alert
		@alert = Alert.new
		size = request.body.read(4).unpack('V')[0]
		message = request.body.read(size - 4)
		aid, @alert.pid, argcount = message.slice!(0, 12).unpack('VVV')
		act = Action.find(aid)
		@alert.action = act
		@alert.ip = request.remote_ip
		@alert.save

		#save parameters
		act.available_function.parameters.all(:order => 'num').each do |param|
			aa = AlertArg.new(:alert => @alert)
			aa.parse(message, param)
			aa.save
		end

		#get info about user/computer/process
		userlen = message.slice!(0, 4).unpack('V')[0]
		@alert.user = message.slice!(0, userlen).force_encoding("UTF-16LE").encode('UTF-8')
		computerlen = message.slice!(0, 4).unpack('V')[0]
		@alert.computer = message.slice!(0, computerlen).force_encoding("UTF-16LE").encode('UTF-8')
		proclen = message.slice!(0, 4).unpack('V')[0]
		@alert.process = message.slice!(0, proclen).force_encoding("UTF-16LE").encode('UTF-8')
		@alert.save

		respond_to do |format|
				format.html { redirect_to @alert, notice: 'Alert was successfully created.' }
				format.json { render json: @alert, status: :created, location: @alert }
		end
	end
end
