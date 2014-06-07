require 'rubygems'
require 'json'
require 'openssl'
require 'SecureRandom'
require 'base64'

unless ARGV.length == 2
	puts "#$0 payload.json sealed.json"
	exit
end

data = File.read(ARGV[0])

path = File.expand_path(File.dirname(__FILE__)) + '/../_shared/public_key.pem'
public_key = OpenSSL::PKey::RSA.new(File.read(path))
rand = SecureRandom.random_bytes(16)
token = public_key.public_encrypt(rand)

cipher = OpenSSL::Cipher.new('rc4')
cipher.encrypt
cipher.key = rand

payload = cipher.update(data) + cipher.final

sealed = {:token => Base64.encode64(token), :payload => Base64.encode64(payload)}

f = File.open(ARGV[1],'w');
f.write(sealed.to_json);
f.close