# Be sure to restart your server when you modify this file.

# Your secret key for verifying the integrity of signed cookies.
# If you change this key, all old signed cookies will become invalid!
# Make sure the secret is at least 30 characters and all random,
# no regular words or you'll be exposed to dictionary attacks.

require 'securerandom'

secret_token_filename = File.join(File.dirname(__FILE__), 'secret_token')
ambush_secret_token = SecureRandom.hex(15)
begin
    f=File.open(secret_token_filename,"r")
    ambush_secret_token = f.read
    f.close
rescue
    f=File.open(secret_token_filename,"w")
    f.write(ambush_secret_token)
    f.close
end

Ambush::Application.config.secret_token = ambush_secret_token
