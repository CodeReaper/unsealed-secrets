require 'rubygems'
require 'json'
require 'openssl'
require 'base64'

unless ARGV.length == 1
	puts "#$0 sealed.json"
	exit
end

text = File.read(ARGV[0])
json = JSON.parse(text)

payload = json["payload"]
token = json["token"]

path = File.expand_path(File.dirname(__FILE__)) + '/../_shared/private_key.pem'
private_key = OpenSSL::PKey::RSA.new(File.read(path))
key = private_key.private_decrypt(Base64.decode64(token))

cipher = OpenSSL::Cipher.new('rc4')
cipher.decrypt
cipher.key = key

unsealed = cipher.update(Base64.decode64(payload)) + cipher.final

puts 'unsealed:'
puts unsealed