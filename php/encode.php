<?php

error_reporting(E_ALL);

if (count($argv) != 3) {
	echo $argv[0], " payload.json sealed.json";
	exit(1);
}

$public_key = openssl_pkey_get_public(file_get_contents(dirname(__FILE__).'/../_shared/public_key.pem'));

$data = file_get_contents($argv[1]);

$sealed = $e = NULL;
openssl_seal($data, $sealed, $e, array($public_key));

$payload = base64_encode($sealed);
$token = base64_encode($e[0]);

$j = new stdClass();
$j->payload = $payload;
$j->token = $token;
$json = json_encode($j);

file_put_contents($argv[2], $json);