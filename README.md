unsealed-secrets
================

A guide to public key encryption in multiple languages.

**Remember** to create your own keys when using the examples, see _shared/create_new_key_pair.sh for help or just run it.

While use public encryption will create seemingly random and different output each time you use it, you still need to protect against unauthorized reusage of a valid and authorized request. My suggestion is to add a timestamp to every request and validate that timestamp against the current time.

All examples will take an arbitrary string and convert into a json string with a payload and token key both with the base64 encoded bytes from the encryption.

## PHP

	php -f php/encode.php _shared/payload.json sealed.json
	php -f php/decode.php sealed.json

## Python

	python python/encode.py _shared/payload.json sealed.json
	python python/decode.py sealed.json

## Ruby

	ruby ruby/encode.rb _shared/payload.json sealed.json
	ruby ruby/decode.rb sealed.json

## Android
Run/See the ExampleTest unit tests.

## iOS
Prepare the project by installing pods

	pod install

Open the workspace and run/see the unit tests.

## C# / Mono

	mcs csharp/encode.cs && mono csharp/encode.exe _shared/payload.json sealed.json
	mcs /reference:System.Web.Extensions.dll csharp/decode.cs && mono csharp/decode.exe sealed.json
