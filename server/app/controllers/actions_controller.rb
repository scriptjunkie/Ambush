class ActionsController < ApplicationController
	protect_from_forgery
	before_filter :login_required
	respond_to :json
	@@memmodes = {'PAGE_EXECUTE' => 0x10, 'PAGE_EXECUTE_READ' => 0x20, 
			'PAGE_EXECUTE_READWRITE' => 0x40, 'PAGE_EXECUTE_WRITECOPY' => 0x80, 
			'PAGE_NOACCESS' => 0x1, 'PAGE_READONLY' => 0x2, 
			'PAGE_READWRITE' => 0x4, 'PAGE_WRITECOPY' => 0x8}
	# DELETE /actions/1.json
	def destroy
		action = Action.find(params[:id])
		func = action.available_function
		func.destroy if func.decl == nil # non-imported function
		action.signature_set.markchanged
		action.destroy
		respond_with({:message => 'Action successfully destroyed!'}, :location => nil)
	end

	# GET /actions/1
	# GET /actions/1.json
	def show
		@action = Action.find(params[:id])
		funct = @action.available_function
		respond_to do |format|
			format.json { render json: {:action => @action, :func => funct.name, 
				:dll => funct.available_dll.name, :params => funct.parameters, 
				:arguments => @action.arguments } }
		end
	end
	
  # POST /actions.json
  # Makes a new signature
	def create
		#Get or create DLL
		dll = AvailableDll.find_or_create(params[:dllCustom])

		#Get or create function
		funcparams = []
		currentParam = 0
		while params["name#{currentParam}"]
			funcparams << {'name' => params["name#{currentParam}"], 'paramtype' => params["type#{currentParam}"],
					'type' => params["subtype#{currentParam}"], 'blobval' => params["blobval#{currentParam}"]}
			currentParam += 1
		end
		func = AvailableFunction.find_or_create(params[:functionCustom], funcparams, dll)
		
		#Create action
		a = Action.new(params[:act])
		a.retval = params[:act][:retval].to_i(16) if params[:act][:retval][0..1] == '0x'
		a.signature_set = SignatureSet.find(params[:signature_set_id])
		a.available_function = func
		a.setAction params[:act][:action]

		#Return address conditions
		if params[:retprotectType] != 'Ignore'
			modeParam = params["subval-1"]
			a.retprotectMode = @@memmodes[modeParam] || modeParam.to_i
			a.retprotectMode = modeParam.to_i(16) if modeParam[0..1] == '0x' # handle 0xabc style
		else
			a.retprotectMode = 0
		end
		a.retprotectType = 0
		a.save

		#Create args
		types = ['Ignore', 'Integer', 'Range', 'C string', 'WC string', 'Pointer', 'Bitmask', 'Blob', 'Not']
		parameters = func.parameters.all(:order => 'num')
		currentParam = 0
		while params["name#{currentParam}"] != nil
			arg = Argument.new(:parameter_id => parameters[currentParam].id, :action => a)

			#get type
			givenType = params["subtype#{currentParam}"]
			arg.argtype = types.index(givenType)
			arg.argtype = types.index(params["type#{currentParam}"]) if arg.argtype == nil
			raise "Error - invalid argument type; try one of these:\n#{types.inspect}" if arg.argtype == nil

			#get val
			arg.regExp = params["val#{currentParam}"] if ['C string', 'WC string', 'Blob'].index(types[arg.argtype])
			arg.setval1(params["val#{currentParam}"]) if ['Integer', 'Range', 'Pointer', 'Bitmask', 'Not'].index(givenType)
			arg.setval2(params["subval#{currentParam}"]) if ['Ranger', 'Bitmask'].index(givenType)
			if(givenType == 'Pointer')
				modeParam = params["subval#{currentParam}"]
				arg.setval2(@@memmodes[modeParam] || modeParam.to_i)
				arg.setval2(modeParam.to_i(16)) if modeParam[0..1] == '0x'
			end

			#must give blob length
			if params["subtype#{currentParam}"] == 'ARG'
				arg.setval1(params["blobval#{currentParam}"])
				arg.val2 = 0
			elsif params["subtype#{currentParam}"] == 'VAL'
				arg.val1 = -1
				arg.setval2(params["blobval#{currentParam}"])
			end
			arg.save
			currentParam += 1
		end

		#we changed the sig set
		a.signature_set.markchanged

		#we're done
		respond_with({:message => 'Signature successfully created!', 
				:row => '<tr><th><input type="checkbox" id="' + a.id.to_s + 
				'_box"></input></th><th scope="row" id="r100">' + 
				ActionController::Base.helpers.strip_tags(a.name) + '</th><td>' + 
				ActionController::Base.helpers.strip_tags(a.available_function.available_dll.name) + 
				'</td><td>' + ActionController::Base.helpers.strip_tags(a.available_function.name) + 
				'</td><td>' + a.actionStr + '</td><td>' + 
				ActionController::Base.helpers.strip_tags(a.arg_str) + '</td></tr>'}, :location => nil)
	end
end
