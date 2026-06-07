@echo off
:: 1. Generate a P-256 Private Key
openssl ecparam -name prime256v1 -genkey -noout -out server_key.pem
:: 2. Generate the X.509 Certificate
openssl req -new -x509 -sha256 -key server_key.pem -out server_crt.pem -days 3650 -subj "/CN=pico2-https"
:: 3. Display for copying
type server_key.pem
type server_crt.pem
pause