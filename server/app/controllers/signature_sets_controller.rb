class SignatureSetsController < ApplicationController
	protect_from_forgery
	before_filter :login_required, :except => [:compiled, :signature]
	respond_to :json
	respond_to :html

	# GET /signature_sets
	# GET /signature_sets.json
	def index
		@signature_sets = SignatureSet.all
		respond_to do |format|
			format.html # index.html.erb
			format.json { render json: @signature_sets }
		end
	end

	# GET /signature_sets/1/compiled
	def compiled
		@signature_set = SignatureSet.find(params[:id])
		send_data @signature_set.compiled
	end

	# GET /signature_sets/1/yaml
	def yaml
		require 'yaml'
		send_data SignatureSet.find(params[:id]).to_yaml, { :type => 'text/plain'.freeze, :disposition => 'inline'.freeze }
	end
 
	# GET /signature_sets/1/signature
	def signature
		@signature_set = SignatureSet.find(params[:id])
		send_data @signature_set.signature
	end

	# GET /signature_sets/1/adm
	def adm
		@signature_set = SignatureSet.find(params[:id])
		headers['Content-Disposition'] = "attachment; filename=\"ambush.adm\""
		respond_to do |format|
			format.html { render	:layout => false, :content_type => 'text/plain' }
			format.json { render json: @signature_set }
		end
	end

	# GET /signature_sets/1
	# GET /signature_sets/1.json
	def show
		@signature_set = SignatureSet.find(params[:id])
		respond_to do |format|
			format.html # show.html.erb
			format.json { render json: @signature_set }
		end
	end

	# GET /signature_sets/new
	# GET /signature_sets/new.json
	def new
		@signature_set = SignatureSet.new(params[:signature_set])
		respond_to do |format|
			format.html # new.html.erb
			format.json { render json: @signature_set }
		end
	end

	# GET /signature_sets/1/edit
	def edit
		@signature_set = SignatureSet.find(params[:id])
	end

	# POST /signature_sets
	# POST /signature_sets.json
	def create
		if params[:imported]
			fin = params[:imported].tempfile
			contents = fin.read fin.stat.size
			fin.close
			@signature_set = SignatureSet.from_simplified(YAML::load(contents),  params[:id])
			redirect_to @signature_set
			return
		end
		@signature_set = SignatureSet.new(params[:signature_set])
		@signature_set.save
		ids = @signature_set.id.to_s
		respond_with({:message => 'Signature successfully created!', 
			:row => '<tr><th id="' + ids + '_box">' + ids + '</th><td><a href="/signature_sets/' + ids + '">View/Edit Signatures</a></td><td><a onclick="deleteSignatureSet(' + ids + ')">Delete Signature Set</a></td></tr>'}, :location => nil)
	end

	# PUT /signature_sets/1
	# PUT /signature_sets/1.json
	def update
		@signature_set = SignatureSet.find(params[:id])
		respond_to do |format|
			if @signature_set.update_attributes(params[:signature_set])
				@signature_set.markchanged
				format.html { redirect_to @signature_set, notice: 'Signature set was successfully updated.' }
				format.json { head :ok }
			else
				format.html { render action: "edit" }
				format.json { render json: @signature_set.errors, status: :unprocessable_entity }
			end
		end
	end

	# DELETE /signature_sets/1
	# DELETE /signature_sets/1.json
	def destroy
		@signature_set = SignatureSet.find(params[:id])
		@signature_set.destroy
		respond_with({:message => 'Signature Set successfully destroyed!'}, :location => nil)
	end
end
