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
		dll = AvailableDll.find(:first, :conditions => {:name => params[:dllCustom]})
		if dll == nil
			dll = AvailableDll.new(:name => params[:dllCustom])
			dll.save
		end

		#Get function
		newFunc = false
		func = AvailableFunction.find(:first, :conditions => 
				{'available_dll_id' => dll.id, 'name' => params[:functionCustom]})

		#Check if we need to make a new one - if it wasn't found or params have changed
		types = ['DONTCARE', 'DWORD', 'DWORDRANGE', 'CSTRING', 'WCSTRING', 'MEM', 'BITMASK', 'BLOB', 'DWORD_NEQ']
		if func != nil
			parameters = func.parameters.all(:order => 'num')
			changed = false
			currentParam = 0
			while params["name#{currentParam}"]
				if currentParam >= parameters.length or parameters[currentParam].name != params["name#{currentParam}"] or
						parameters[currentParam].paramtype != types.index(params["type#{currentParam}"])
					changed = true
					break
				end
				currentParam += 1
			end
		else
			changed = true
		end

		if changed   #make a new func
			func = AvailableFunction.new(:name => params[:functionCustom], :available_dll => dll)
			func.save

			#add params
			currentParam = 0
			while params["name#{currentParam}"] != nil
				p = Parameter.new(:name => ActionController::Base.helpers.strip_tags(params["name#{currentParam}"]), 
						:num => currentParam+1, :available_function => func)
				p.paramtype = types.index(params["type#{currentParam}"])
				raise "Error - invalid parameter type; try one of these:\n#{types.inspect}" if p.paramtype == nil

				if params["type#{currentParam}"] == 'BLOB' #must give blob length
					p.arg = params["blobval#{currentParam}"] if params["subtype#{currentParam}"] == 'ARG'
					p.size = params["blobval#{currentParam}"] if params["subtype#{currentParam}"] == 'VAL'
				end
				p.save
				currentParam += 1
			end
		end

		#Create action
		a = Action.new(params[:act])
		if params[:act][:retval][0..1] == '0x'
			a.retval = params[:act][:retval][2..-1].to_i(16)
		end
		a.signature_set = SignatureSet.find(params[:signature_set_id])
		a.available_function = func
		a.setAction params[:act][:action]

		#Return address conditions
		if params[:retprotectType] != 'DONTCARE'
			modeParam = params["subval-1"]
			memmode = @@memmodes[modeParam]
			memmode = modeParam.to_i if memmode == nil
			a.retprotectMode = memmode
		else
			a.retprotectMode = 0
		end
		a.retprotectType = 0
		a.save

		#Create args
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
			arg.regExp = params["val#{currentParam}"] if ['CSTRING', 'WCSTRING', 'BLOB'].index(types[arg.argtype])
			arg.setval1(params["val#{currentParam}"]) if ['DWORD', 'DWORDRANGE', 'MEM', 'BITMASK', 'DWORD_NEQ'].index(givenType)
			arg.setval2(params["subval#{currentParam}"]) if ['DWORDRANGE', 'BITMASK'].index(givenType)
			if(givenType == 'MEM')
				modeParam = params["subval#{currentParam}"]
				memmode = @@memmodes[modeParam]
				memmode = modeParam.to_i if memmode == nil
				arg.setval2(memmode)
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
