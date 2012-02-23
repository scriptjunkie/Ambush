class SignatureSet < ActiveRecord::Base
	has_many :actions, :dependent => :destroy

	def cachepath
		File.join(File.dirname(__FILE__), '..', 'assets', 'sigs', self.id.to_s + '_compiled')
	end

	def signaturepath
		File.join(File.dirname(__FILE__), '..', 'assets', 'sigs', self.id.to_s + '_signature')
	end

	def signature
		if File.file? self.signaturepath
			fin = File.open(self.signaturepath, 'rb')
			data = fin.read fin.stat.size
			fin.close
			return data
		end
		data = sign(self.compiled)
		fout = File.open(self.signaturepath, 'wb')
		fout.write data
		fout.close
		data
	end

	def markchanged
		File.unlink self.signaturepath if File.exists? self.signaturepath
		File.unlink self.cachepath if File.exists? self.cachepath
	end

	def compiled
		if File.file? self.cachepath
			fin = File.open(self.cachepath, 'rb')
			data = fin.read fin.stat.size
			fin.close
			return data
		end
		
		self.serial = 1 if self.serial == nil
		self.version = 1 if self.serial == nil
		out = [self.version, self.serial].pack('eV')
		# set ourselves as default report IP
		self.report = getDefaultIp if self.report == nil
		mname = self.report.to_s
		mname = mname + ("\x00"* (4-(mname.length % 4)) )

		dlls = AvailableDll.find(:all,:joins => "INNER JOIN available_functions ON available_functions.available_dll_id = available_dlls.id INNER JOIN actions ON available_functions.id = actions.available_function_id",:select => 'DISTINCT(available_dlls.name),available_dlls.*')
		numdlls = 0
		temp = ''
		dlls.each do |dll|
			dlcompiled = dll.compiled(self.id)
			if(dlcompiled.length > 0)
				temp << dlcompiled
				numdlls += 1
			end
		end

		out << [numdlls, mname.length].pack("V*") + mname + temp
		# version, serialNumber, numdlls, pipeNameLen, pipeName, dlls[]
		fout = File.open(self.cachepath, 'wb')
		fout.write out
		fout.close
		out
	end

	# Key mgmt functions
	#Generate a new key pair
	def genkeys
		privkey = `openssl genpkey -algorithm RSA`

		f = open(self.privpath, 'wb')
		f.write(privkey)
		f.close

		proc = IO.popen('openssl pkey -pubout','w+')
		proc.write(privkey)
		proc.close_write
		pubkey = proc.read
		proc.close

		f = open(self.pubpath, 'wb')
		f.write(pubkey)
		f.close
	end

	def pubpath
		File.join(File.dirname(__FILE__), '..', '..', 'public', 'public.key')
	end

	def privpath
		File.join(File.dirname(__FILE__), '..', 'assets', 'sigs', 'private.key')
	end

	def pubkey
		genkeys if not File.file? self.pubpath
		return IO.read(self.pubpath)
	end

	def sign(data)
		genkeys if not File.file? self.privpath
		proc = IO.popen('openssl dgst -sign "' + self.privpath + '"','w+')
		proc.write(data)
		proc.close_write
		dgst = proc.read
		proc.close
		dgst
	end

	def simplified
		{'report' => self.report, 'version' => self.version, 'actions' => self.actions.map{|a| a.simplified} }
	end

	def self.from_simplified(simple, setid)
		if setid
			@signature_set = SignatureSet.find(setid)
		else
			@signature_set = SignatureSet.new(:report => simple['report'], :version => simple['version'])
			@signature_set.save
		end
		simple['actions'].each do |act|
			begin
				Action.from_simplified(act, @signature_set)
			rescue Exception => e
				Rails.logger.error e
				Rails.logger.error e.backtrace
			end
		end
		@signature_set
	end

	def to_yaml
		self.simplified.to_yaml
	end

	def getDefaultIp
		begin
			require 'socket'
			sock = UDPSocket.open
			sock.connect('1.2.3.4', 1234)
			add = sock.addr.last
			sock.close
		rescue ::Exception
			return '127.0.0.1'
		end
		add
	end

end
