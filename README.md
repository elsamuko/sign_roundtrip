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
SHA256    : I6y8EgCFG2H6PTHVZyHR10nnN1FZnvvxv8Izrut+Jgs=
OK        : true
Signature : kCbtJcwGaB8f4LkFrw1yPlcKLjkQdhBErJisgkpNuLv55sQ1O0bEaV0klrQr9us7BXZOSdIOXS/D20iFhr9Sge9+9weRRNpo+hdoDnC5VagqmuWlenhwG9mMj6//aV8HEeeoIEYljSMQTug4MErSr44+uyyx34B51XlFpbkBtG4lk0oO69ZfYe1EWHqYIeOfySOV14Gek/h4JdR0+CEgWpaqUL1Iz4iztucWid0aas/6GbzswY6zE2+7SIC3jpv4JFU9ehacMcNw7jkWdCVYeUm/2aJuwIbe4cuMmnpIFGAbFhdZ6SkLM5xwmkdgjzvu/a+bbj/Y2kBxmv62t9bhYQ==

Groovy: 
SHA256    : I6y8EgCFG2H6PTHVZyHR10nnN1FZnvvxv8Izrut+Jgs=
OK        : true
Signature : kCbtJcwGaB8f4LkFrw1yPlcKLjkQdhBErJisgkpNuLv55sQ1O0bEaV0klrQr9us7BXZOSdIOXS/D20iFhr9Sge9+9weRRNpo+hdoDnC5VagqmuWlenhwG9mMj6//aV8HEeeoIEYljSMQTug4MErSr44+uyyx34B51XlFpbkBtG4lk0oO69ZfYe1EWHqYIeOfySOV14Gek/h4JdR0+CEgWpaqUL1Iz4iztucWid0aas/6GbzswY6zE2+7SIC3jpv4JFU9ehacMcNw7jkWdCVYeUm/2aJuwIbe4cuMmnpIFGAbFhdZ6SkLM5xwmkdgjzvu/a+bbj/Y2kBxmv62t9bhYQ==

Bash: 
SHA256    : I6y8EgCFG2H6PTHVZyHR10nnN1FZnvvxv8Izrut+Jgs=
OK        : true
Signature : kCbtJcwGaB8f4LkFrw1yPlcKLjkQdhBErJisgkpNuLv55sQ1O0bEaV0klrQr9us7BXZOSdIOXS/D20iFhr9Sge9+9weRRNpo+hdoDnC5VagqmuWlenhwG9mMj6//aV8HEeeoIEYljSMQTug4MErSr44+uyyx34B51XlFpbkBtG4lk0oO69ZfYe1EWHqYIeOfySOV14Gek/h4JdR0+CEgWpaqUL1Iz4iztucWid0aas/6GbzswY6zE2+7SIC3jpv4JFU9ehacMcNw7jkWdCVYeUm/2aJuwIbe4cuMmnpIFGAbFhdZ6SkLM5xwmkdgjzvu/a+bbj/Y2kBxmv62t9bhYQ==

```
