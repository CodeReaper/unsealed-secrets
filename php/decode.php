<?php

error_reporting(E_ALL);

if (count($argv) != 2) {
	echo $argv[0], " sealed.json";
	exit(1);
}

$private_key = openssl_get_privatekey(file_get_contents(dirname(__FILE__).'/../_shared/private_key.pem'));

$sealed = file_get_contents($argv[1]);
$sealed = json_decode($sealed);

$token = $sealed->token;
$payload = $sealed->payload;

$unsealed = NULL;
openssl_open(base64_decode($payload), $unsealed, base64_decode($token), $private_key);

echo "unsealed:\n$unsealed\n";