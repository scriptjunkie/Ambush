require 'socket'
class SignatureSet < ActiveRecord::Base
	has_many :actions, :dependent => :destroy
	# if the signature_version does not match what the client agents were built for, it 
	# will trigger an update
	@@signature_version = 1.01

	def cachepath
		File.join(File.dirname(__FILE__), '..', 'assets', 'sigs', self.id.to_s + '_compiled')
	end

	def signaturepath
		File.join(File.dirname(__FILE__), '..', 'assets', 'sigs', self.id.to_s + '_signature')
	end

	def self.installerpath
		File.join(File.dirname(__FILE__), '..', '..', 'public', 'installer.msi')
	end

	def self.installersigpath
		File.join(File.dirname(__FILE__), '..', 'assets', 'sigs', 'installer_sig')
	end

	# provides a signature for an arbitrary block of data, cached with a file path
	def self.get_signature(sigpath)
		# use cached if present
		if File.file? sigpath
			fin = File.open(sigpath, 'rb')
			data = fin.read fin.stat.size
			fin.close
			return data
		end
		# otherwise generate and save
		data = sign(yield)
		fout = File.open(sigpath, 'wb')
		fout.write data
		fout.close
		data
	end

	# provides a signature for the compiled signature set
	def signature
		SignatureSet.get_signature(signaturepath){ self.compiled }
	end

	# provides a signature for the client binary installer
	def self.installer_sig
		self.get_signature(self.installersigpath) do
			fin = File.open(self.installerpath, 'rb')
			data = fin.read fin.stat.size
			fin.close
			data
		end
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
		out = [@@signature_version, self.serial].pack('eV')
		reserved = '' # not currently used
		blist = ApplicationHelper.splitregex(self.procblacklist.to_s) # handles regex formatting, encoding and padding

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

		out << [numdlls, reserved.length, blist.length].pack("V*") + reserved + blist + temp
		# version, serialNumber, numdlls, pipeNameLen, pipeName, dlls[]
		fout = File.open(self.cachepath, 'wb')
		fout.write out
		fout.close
		out
	end

	# Key mgmt functions
	#Generate a new key pair
	def self.genkeys
		privkey = `openssl genrsa 2048`

		f = open(self.privpath, 'wb')
		f.write(privkey)
		f.close

		proc = IO.popen('openssl rsa -pubout','w+')
		proc.write(privkey)
		proc.close_write
		pubkey = proc.read
		proc.close

		f = open(self.pubpath, 'wb')
		f.write(pubkey)
		f.close
	end

	def self.pubpath
		File.join(File.dirname(__FILE__), '..', '..', 'public', 'public.key')
	end

	def self.privpath
		File.join(File.dirname(__FILE__), '..', 'assets', 'sigs', 'private.key')
	end

	def self.pubkey
		genkeys if not File.file? self.pubpath
		return IO.read(self.pubpath)
	end

	def self.sign(data)
		genkeys if not File.file? self.privpath
		proc = IO.popen('openssl dgst -sha1 -sign "' + self.privpath + '"','wb+')
		proc.write(data)
		proc.close_write
		dgst = proc.read
		proc.close
		dgst
	end

	def simplified
		{'version' => @@signature_version, 'procblacklist' => self.procblacklist, 'actions' => self.actions.map{|a| a.simplified} }
	end

	def self.from_simplified(simple, setid)
		# This is where we could do version checks with simple['version'] if the format changes
		if setid
			@signature_set = SignatureSet.find(setid)
		else
			@signature_set = SignatureSet.new()
			if simple['procblacklist']
				@signature_set.procblacklist = simple['procblacklist']
			end
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
			sock = UDPSocket.open
			sock.connect('1.2.3.4', 1234)
			add = sock.addr.last
			sock.close
		rescue ::Exception
			return '127.0.0.1'
		end
		add
	end

	# sends message to the aggregator
	def sendSyslog(message)
		return if self.aggregator == nil or self.aggregator.length == 0
		self.aggregator_port = 514 if self.aggregator_port == nil or self.aggregator_port == 0
		begin
			s = UDPSocket.new
			s.send message, 0, self.aggregator, self.aggregator_port
			s.close
		rescue Exception => e
			Rails.logger.error e
			Rails.logger.error e.backtrace
		end
	end
end
