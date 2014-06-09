openssl genrsa -out private_key.pem 2048
openssl rsa -in private_key.pem -outform PEM -pubout -out public_key.pem
#because java is rather hard to work with :
openssl pkcs8 -topk8 -inform PEM -outform DER -in private_key.pem -out private_key.der -nocrypt
openssl rsa -in private_key.pem -pubout -outform DER -out public_key.der
#because objective-c is even harder :
openssl req -new -key private_key.pem -out certificate_request.csr -subj '/CN=www.example.com/O=Example LTD./C=US'
openssl x509 -req -days 3650 -in certificate_request.csr -signkey private_key.pem -out public_certificate.crt
openssl x509 -outform der -in public_certificate.crt -out public_certificate.der
openssl pkcs12 -export -out private_p12.p12 -inkey private_key.pem -in public_certificate.crt -passin pass: -passout pass:
rm certificate_request.csr
rm public_certificate.crt