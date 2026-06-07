// certs.h
// TUKE - Nikita Kuropatkin
// Self-signed certificate and private key for HTTPS server

#ifndef CERTS_H
#define CERTS_H

/* ============================================================
 * X.509 SERVER CERTIFICATE (ECDSA P-256)
 * ------------------------------------------------------------
 * This is your public "Digital ID" that your Pico sends to the 
 * web browser during the TLS handshake. 
 * ============================================================ */
const char srv_crt_pem[] =
"-----BEGIN CERTIFICATE-----\n"
"MIIBgTCCASegAwIBAgIUGmGGWSReiuso9IbfsVO6gKBNMeEwCgYIKoZIzj0EAwIw\n"
"FjEUMBIGA1UEAwwLcGljbzItaHR0cHMwHhcNMjYwNTEyMTExNjE4WhcNMzYwNTA5\n"
"MTExNjE4WjAWMRQwEgYDVQQDDAtwaWNvMi1odHRwczBZMBMGByqGSM49AgEGCCqG\n"
"SM49AwEHA0IABCoGqWXyAiSWcK8vt1M+X9IOOUYhCVd52ch9lfBCJsEfNO0y1hXq\n"
"40FpnkOkVoRuDruAaEP3XbAUPZqZ+Xgh7dSjUzBRMB0GA1UdDgQWBBTEMaji47VD\n"
"mo0sgtMBckgXsNwDVDAfBgNVHSMEGDAWgBTEMaji47VDmo0sgtMBckgXsNwDVDAP\n"
"BgNVHRMBAf8EBTADAQH/MAoGCCqGSM49BAMCA0gAMEUCIQCoAdfXHWcdP61H/yoU\n"
"8csJmS031PEDZRW8civcw/w6OgIgZdrPwqil8cOthByugZjHQkkcLFDRUiEpVKKL\n"
"GGM1S5I=\n"
"-----END CERTIFICATE-----\n";

/* ============================================================
 * SERVER PRIVATE KEY (ECDSA P-256)
 * ------------------------------------------------------------
 * This is the secret key used to prove ownership of the 
 * certificate. This must match the ECDSA algorithm expected 
 * by the browser.
 * ============================================================ */
const char srv_key_pem[] =
"-----BEGIN EC PRIVATE KEY-----\n"
"MHcCAQEEIKPrB6XNbj5Nr95Un2miuLPMZMXmodihhHWApqjCsRwqoAoGCCqGSM49\n"
"AwEHoUQDQgAEKgapZfICJJZwry+3Uz5f0g45RiEJV3nZyH2V8EImwR807TLWFerj\n"
"QWmeQ6RWhG4Ou4BoQ/ddsBQ9mpn5eCHt1A==\n"
"-----END EC PRIVATE KEY-----\n";

#endif // CERTS_H
