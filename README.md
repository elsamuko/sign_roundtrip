sign_roundtrip
==============

Sign and verify data with C/C++, Groovy/Java and Bash

These are three sample programs, which sign and verify a random text with a RSA PEM key pair with the 
help of the OpenSSL library. The signature of all three programs are identical. 
This can be useful, if you need verified interlanguage communication or for testing purposes (e.g. with 
curl).

Just start the script with ./run_all.sh from the main directory, the output should be:

```bash
C++: 
SHA1      : 0HCrwavWOUBCdySetlbrzqX196E=
OK        : true
Signature : K8Ml5J7spAy9p246MKgKYRLLSnlLB9svVzThhKq/ffZnbbvS7YtMV9+FO2iaA7iWKWtovYjngXjn0DPwySyJO0eSQHylGXZI3khZHcZRKwLXET2uPTtEMavT8eYtLlrQpeMnZbyhq4Uwc/4XCYDe+jGOLK4aqJobOPuy2u1wsrU=

Groovy: 
SHA1      : 0HCrwavWOUBCdySetlbrzqX196E=
OK        : true
Signature : K8Ml5J7spAy9p246MKgKYRLLSnlLB9svVzThhKq/ffZnbbvS7YtMV9+FO2iaA7iWKWtovYjngXjn0DPwySyJO0eSQHylGXZI3khZHcZRKwLXET2uPTtEMavT8eYtLlrQpeMnZbyhq4Uwc/4XCYDe+jGOLK4aqJobOPuy2u1wsrU=

Bash: 
SHA1      : 0HCrwavWOUBCdySetlbrzqX196E=
OK        : true
Signature : K8Ml5J7spAy9p246MKgKYRLLSnlLB9svVzThhKq/ffZnbbvS7YtMV9+FO2iaA7iWKWtovYjngXjn0DPwySyJO0eSQHylGXZI3khZHcZRKwLXET2uPTtEMavT8eYtLlrQpeMnZbyhq4Uwc/4XCYDe+jGOLK4aqJobOPuy2u1wsrU=
```
