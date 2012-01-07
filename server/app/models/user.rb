require 'digest/sha1'
class User < ActiveRecord::Base
	attr_accessible :username, :password, :password_confirmation
	attr_accessor :password
	before_save :prepare_password

	validates_presence_of :password, :on => :create
	validates_confirmation_of :password
	validates_length_of :password, :minimum => 4, :allow_blank => true

	# login can be either username or email address
	def self.authenticate(login, pass)
		user = find_by_username(login)
		return user if user && user.matching_password?(pass)
	end

	def matching_password?(pass)
		self.password_hash == encrypt_password(pass)
	end

	private

	def prepare_password
		unless password.blank?
			# gen salt
			chars = ("a".."z").to_a + ("A".."Z").to_a + ("0".."9").to_a
			self.password_salt = ""
			1.upto(10) do |i| 
				self.password_salt << chars[rand(chars.size-1)]
			end
			self.password_hash = encrypt_password(password)
		end
	end

	def encrypt_password(pass)
		Digest::SHA1.hexdigest(pass + password_salt)
	end
end
