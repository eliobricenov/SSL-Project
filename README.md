# SSL project made with OpenSSL and Java EE

Make sure to install OpenSSL in your machine, you can download it [here](https://www.openssl.org/).

To generate an SSL public - private key pair use the following command:

```bat
openssl genrsa -out your_key_name.pem 1024
```
 To extract the public key use:

 ```bat
 openssl rsa -in mykey.pem -pubout > mykey.pub
 ```

 And to extract the private key use the following command, **make sure it is a PCKS8 format so that Java won't have troubles reading it**:

 ```bat
openssl pkcs8 -topk8 -inform PEM -in private.pem -out private_key.pem -nocrypt
 ```