# SSL/TLS Handshake Simulation with Certificate Verification

Ky projekt eshte nje aplikacion console ne Python qe simulon procesin kryesor te SSL/TLS Handshake me verifikim certifikate. Projekti eshte ndertuar si model `client-server`, ku serveri dergon certifikaten e tij, klienti e verifikon ate me nje Certificate Authority te besuar dhe pastaj te dy palet krijojne nje session key per komunikim te enkriptuar.

Qellimi i projektit eshte edukativ: te tregoje ne menyre praktike si funksionojne PKI, certifikatat, key exchange dhe komunikimi i sigurt.

## Objektivat

Ky projekt demonstron:

- simulimin e hapave kryesore te SSL/TLS Handshake
- krijimin e nje CA-je dhe certifikate serveri
- verifikimin e certifikates se serverit nga klienti
- shkembimin e celesave me ECDH
- krijimin e nje symmetric session key me HKDF
- komunikimin e enkriptuar me AES-GCM
- logimin e hapave ne server dhe klient
- menaxhimin e gabimeve kur certifikata eshte e pavlefshme

## Struktura e Projektit

```text
SSL_TLS_Handshake_Project/
  certificates/
    ca_cert.pem
    ca_key.pem
    server_cert.pem
    server_key.pem

  client/
    client.py

  server/
    server.py

  logs/
    client_log.txt
    server_log.txt
    certificate_inspector_log.txt

  generate_cer.py
  certificate_inspector.py
  requirements.txt
  README.md
```

## Pershkrimi i File-ave

`generate_cer.py`  
Gjeneron certifikatat dhe private keys. Ky file krijon nje CA certificate dhe nje server certificate te nenshkruar nga CA.

`server/server.py`  
Starton serverin, pret lidhje nga klienti, dergon certifikaten, kryen Server Key Exchange dhe pranon mesazhe te enkriptuara.

`client/client.py`  
Starton klientin, nis handshake-in, merr certifikaten e serverit, e verifikon ate dhe krijon komunikim te sigurt me serverin.

`certificate_inspector.py`  
Kontrollon certifikatat pa startuar serverin/klientin. Shfaq detajet e certifikates dhe verifikon nese server certificate eshte e nenshkruar nga CA e besuar.

`requirements.txt`  
Permban librarine e nevojshme:

```text
cryptography
```

`logs/`  
Permban loget e serverit, klientit dhe certificate inspector.

## Teknologjite e Perdorura

Projekti perdor Python dhe librarine `cryptography`.

Algoritmet kryesore:

- `RSA 2048-bit` per CA dhe certifikaten e serverit
- `X.509` per certifikata digjitale
- `ECDH SECP256R1` per key exchange
- `HKDF SHA-256` per derivimin e session key
- `AES-GCM` per enkriptim dhe integritet te mesazheve
- `SHA-256` per hashing/signature verification

## Instalimi

Hape projektin ne PyCharm ose terminal dhe sigurohu qe je ne folderin kryesor:

```powershell
cd SSL_TLS_Handshake_Project
```

Instalo dependency-t:

```powershell
pip install -r requirements.txt
```

Ose:

```powershell
py -m pip install -r requirements.txt
```

## Gjenerimi i Certifikatave

Para se te startosh serverin dhe klientin, duhet te gjenerohen certifikatat:

```powershell
py generate_cer.py
```

Kjo komande krijon:

```text
certificates/ca_cert.pem
certificates/ca_key.pem
certificates/server_cert.pem
certificates/server_key.pem
```

`ca_cert.pem` perdoret nga klienti si CA e besuar.  
`server_cert.pem` dergohet nga serveri gjate handshake-it.  
`server_key.pem` perdoret nga serveri per te nenshkruar Server Key Exchange.

## Certificate Inspector

Per te kontrolluar certifikatat pa startuar serverin dhe klientin:

```powershell
py certificate_inspector.py
```

Ky file kontrollon:

- nese certifikata eshte brenda dates se vlefshmerise
- nese certifikata i perket `localhost`
- nese certifikata e serverit eshte nenshkruar nga CA e besuar
- detajet kryesore te certifikates, si issuer, subject, serial number dhe validity period

Output-i ruhet edhe ne:

```text
logs/certificate_inspector_log.txt
```

## Ekzekutimi i Projektit

### 1. Starto Serverin

Ne terminalin e pare:

```powershell
py server/server.py
```

Serveri duhet te shfaqe:

```text
Server started and listening for connections on port 8443...
```

### 2. Starto Klientin

Ne terminalin e dyte:

```powershell
py client/client.py
```

Klienti do te nise SSL/TLS handshake dhe do te verifikoje certifikaten e serverit.

## Shembull Output - Klienti

```text
Welcome to the SSL/TLS Handshake Simulation Client.
Attempting to establish a secure connection with the server...
Client Hello sent.
Server Hello received. Cipher suite: TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
Server certificate received. Verifying...
Server certificate is valid.
Server Key Exchange signature verified.
Certificate Request received.
Server Hello Done received.
Client Certificate message sent.
Client Key Exchange sent.
Derived symmetric AES session key.
Certificate Verify sent.
Change Cipher Spec sent.
Finished message sent.
SSL/TLS handshake successful. Secure communication channel established.
Encrypted application data sent to server.
Secure server response: Mesazhi u mor ne menyre te sigurt.
```

## Shembull Output - Serveri

```text
Server started and listening for connections on port 8443...
Incoming connection from 127.0.0.1:61513
SSL/TLS handshake initiated with client...
Received Client Hello.
Sent Server Hello.
Sending server certificate...
Sent Server Key Exchange.
Sent Certificate Request.
Sent Server Hello Done.
Received Client Certificate message.
Received Client Key Exchange.
Derived symmetric session key.
Received Certificate Verify.
Received Change Cipher Spec.
Client has verified the certificate. Handshake complete.
Encrypted message received and decrypted: Pershendetje nga klienti!
Encrypted response sent to client.
```

## Test me Certifikate te Pavlefshme

Projekti perfshin edhe nje test per error handling. Serveri mund te startohet me certifikate te manipuluar:

```powershell
py server/server.py --tamper-cert
```

Pastaj starto klientin:

```powershell
py client/client.py
```

Klienti duhet ta refuzoje handshake-in dhe te shfaqe:

```text
Handshake failed: Server certificate signature is invalid.
```

Ky test tregon qe klienti nuk pranon certifikata qe nuk jane te nenshkruara nga CA e besuar.

## Hapat e Simuluar te SSL/TLS Handshake

Projekti simulon keto hapa:

1. `Client Hello` - klienti dergon versionin, cipher suites dhe nonce.
2. `Server Hello` - serveri zgjedh cipher suite dhe dergon nonce.
3. `Certificate` - serveri dergon certifikaten e tij.
4. `Certificate Verification` - klienti verifikon certifikaten me CA te besuar.
5. `Server Key Exchange` - serveri dergon public key per ECDH dhe e nenshkruan ate.
6. `Certificate Request` - serveri kerkon certifikate nga klienti ne menyre simuluese.
7. `Server Hello Done` - serveri perfundon pjesen e tij te pare te handshake-it.
8. `Client Certificate` - klienti dergon identitet demonstrues.
9. `Client Key Exchange` - klienti dergon public key per ECDH.
10. `Certificate Verify` - klienti njofton qe certifikata u verifikua.
11. `Change Cipher Spec` - palet kalojne ne komunikim te enkriptuar.
12. `Finished` - konfirmohet perfundimi i handshake-it.
13. `Secure Data` - dergohen mesazhe te enkriptuara me AES-GCM.

## Si Plotesohen Kerkesat e Projektit

`Technical Stack`  
Projekti ka nje server console dhe nje client console ne Python.

`Certificate Verification`  
Klienti verifikon certifikaten e serverit duke kontrolluar daten e vlefshmerise, identitetin `localhost` dhe nenshkrimin nga CA e besuar.

`Key Exchange`  
Perdor ECDH per krijimin e shared secret dhe HKDF per derivimin e session key.

`Secure Communication`  
Pas handshake-it, komunikimi behet me AES-GCM.

`Logging and Monitoring`  
Serveri, klienti dhe certificate inspector shkruajne loge ne folderin `logs`.

`Error Handling`  
Projekti trajton gabime si certifikata e pavlefshme, mungesa e certifikatave dhe humbja e lidhjes.

`Documentation`  
Ky README shpjegon instalimin, ekzekutimin, testimin dhe funksionimin e projektit.

## Renditja e Ekzekutimit per Prezantim

```powershell
py generate_cer.py
py certificate_inspector.py
py server/server.py
py client/client.py
```

Per rastin me certifikate te pavlefshme:

```powershell
py server/server.py --tamper-cert
py client/client.py
```

## Shenim Final

Ky projekt eshte simulim edukativ i SSL/TLS Handshake. Ai perdor algoritme reale kriptografike per demonstrim, por nuk zevendeson implementimet reale te TLS qe perdoren ne sisteme production.
