PROJECT IN DEVELOPMENT PHASE! Don't use in production.

Project supports following ciphers of ssl 3.0:
* EDH-DSS-DES-CBC3-SHA
* EDH-DSS-DES-CBC-SHA
* EDH-RSA-DES-CBC3-SHA
* DES-CBC3-SHA
* ADH-DES-CBC3-SHA
* ADH-DES-CBC-SHA
* EDH-RSA-DES-CBC-SHA
* DES-CBC-SHA
* EXP-EDH-RSA-DES-CBC-SHA
* EXP-EDH-DSS-DES-CBC-SHA
* EXP-DES-CBC-SHA (need to use week rsa key)
* EXP-ADH-DES-CBC-SHA
* RC4-SHA

Support features:
* session resumption

It has been tested with openssl 0.9.7e.
Not all the features work but let's hope they will soon :)
