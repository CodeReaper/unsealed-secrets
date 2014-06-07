unsealed-secrets
================

A guide to public key encryption in multiple languages.

Remember to create your own keys when using the examples, see _shared/create_new_key_pair.sh for help or just run it.

PHP
===

	php -f php/encode.php _shared/payload.json sealed.json
	php -f php/decode.php sealed.json

Python
======

	python python/encode.py _shared/payload.json sealed.json
	python python/decode.py sealed.json

Ruby
====

	ruby ruby/encode.rb _shared/payload.json sealed.json
	ruby ruby/decode.rb sealed.json

Android
=======
Run/See the ExampleTest unit test.