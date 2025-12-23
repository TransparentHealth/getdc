Get Direct Certificate - A Toolkit for Certificate Discovery in DNS and LDAP
============================================================================


GetDC is a set of tools designed to simplify and automate Direct certificate
discovery. It can however, can be used to fetch any x509 certificate from LDAP
or DNS.

For more information on Direct see 
http://wiki.directproject.org/Applicability_Statement_for_Secure_Health_Transport and 
https://www.healthit.gov/test-method/direct-project


The toolkit includes the following:

* A micro web-service for fetching certificate discovery results.
* Command-line utility for fetching and downloading certificates

System Behavior
---------------

An address or domain is supplied as input to the command line utility or webservice.
The output is a JSON document containing results. A top level Boolean
variable `is_found` contains the flag indicating
if a certificate was found or not.

If an email address is presented the tool will first attempt to look up and
return a email bound certificate.  If that fails, the tool will attempt to
look up an domain-bound certificate. The response will indicate whether a
domain-bound or email-bound certificate was retrieved. For this feature to work,
use the "@" symbol in the endpoint and not the DNS representation.
(e.g. "john@direct.example.com" instead of "john.direct.example.com".


Installation
------------

You need to make sure you have the prerequisites for the application.
The following instructions are for Ubuntu.

    sudo apt-get install -y python-ldap python-dnspython python-openssl
    
If you are using Redhat, CentOS, or Fedora, install the prereqisuites with the following command.


    sudo yum install redhat-rpm-config gcc libffi-devel python-devel openssl-devel

    
...then you can install with pip

    sudo pip install getdc

...or to install from source or into a virtualenv (on Ubuntu):


    sudo apt-get install -y build-essential python3-dev libldap-dev libsasl2-dev libffi-dev libssl-dev 
    sudo pip install getdc



Command Line Utility
====================

A response is printed as JSON to stdout indicating whether the certificate was found or
not via LDAP or DNS.  It also includes details about the certificates.

Usage:
    
    get_direct_certificate.py [email/endpoint] [-d]

Example 1: Discover a certificate via DNS and download the certificate. Pass the optional `-d` flag to also download certificates found.

    $ get_direct_certificate.py ett.healthit.gov -d
    
    {
        "is_found": true, 
        "dns": {
            "status": 200, ett.healthit.gov Y
            "cert_details": [
                {
                    "is_expired": false
                }
            ], 
            "message": "The certificate ett.healthit.gov was found.", 
            "is_found": true,
            ...omitted for brevity...
        }, 
        "ldap": {
            "status": 404, 
            "message": "No certificate found.", 
            "is_found": false, 
            "details": "No LDAP server was found."
        }
    }

Example 1.1: Print out the resulting PEM certificate as text.

    > cat ett.healthit.gov.pem
    -----BEGIN CERTIFICATE-----
    MIIEoTCCA4mgAwIBAgICAacwDQYJKoZIhvcNAQELBQAwgY0xCzAJBgNVBAYTAlVTMQswCQYDVQQI
    DAJNRDEOMAwGA1UEBwwFQm95ZHMxEzARBgNVBAoMCkRyYWplciBMTEMxIjAgBgNVBAMMGWludGVy
    bWVkaWF0ZS5oZWFsdGhpdC5nb3YxKDAmBgkqhkiG9w0BCQEWGWludGVybWVkaWF0ZS5oZWFsdGhp
    dC5nb3YwHhcNMTgwOTI1MTgyNDIzWhcNMjgwOTIyMTgyNDIzWjB7MQswCQYDVQQGEwJVUzELMAkG
    A1UECAwCTUQxDjAMBgNVBAcMBUJveWRzMRMwEQYDVQQKDApEcmFqZXIgTExDMRkwFwYDVQQDDBBl
    dHQuaGVhbHRoaXQuZ292MR8wHQYJKoZIhvcNAQkBFhBldHQuaGVhbHRoaXQuZ292MIIBIjANBgkq
    hkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxaA2MIuaqpvP2Id85KIhUVA6zlj+CgZh/3prgJ1q4leP
    3T5F1tSSgrQ/WYTFglEwN7FJx4yJ324NaKncaMPDBIg3IUgC3Q5nrPUbIJAUgM5+67pXnGgt6s9b
    QelEsTdbyA/JlLC7Hsv184mqo0yrueC9NJEea4/yTV51G9S4jLjnKhr0XUTw0Fb/PFNL9ZwaEdFg
    QfUaE1maleazKGDyLLuEGvpXsRNs1Ju/kdHkOUVLf741Cq8qLlqOKN2v5jQkUdFUKHbYIF5KXt4T
    oV9mvxTaz6Mps1UbS+a73Xr+VqmBqmEQnXA5DZ7ucikzv9DLokDwtmPzhdqye2msgDpw0QIDAQAB
    o4IBGjCCARYwCQYDVR0TBAIwADAbBgNVHREEFDASghBldHQuaGVhbHRoaXQuZ292MB0GA1UdDgQW
    BBQ6E22jc99mm+WraUj93IvQcw6JHDAfBgNVHSMEGDAWgBRfW20fzencvG+Attm1rcvQV+3rOTAL
    BgNVHQ8EBAMCBaAwSQYDVR0fBEIwQDA+oDygOoY4aHR0cDovL2NhLmRpcmVjdGNhLm9yZy9jcmwv
    aW50ZXJtZWRpYXRlLmhlYWx0aGl0Lmdvdi5jcmwwVAYIKwYBBQUHAQEESDBGMEQGCCsGAQUFBzAC
    hjhodHRwOi8vY2EuZGlyZWN0Y2Eub3JnL2FpYS9pbnRlcm1lZGlhdGUuaGVhbHRoaXQuZ292LmRl
    cjANBgkqhkiG9w0BAQsFAAOCAQEAhCASLubdxWp+XzXO4a8zMgWOMpjft+ilIy2ROVKOKslbB7lK
    x0NR7chrTPxCmK+YTL2ttLaTpOniw/vTGrZgeFPyXzJCNtpnx8fFipPE18OAlKMc2nyy7RfUscf2
    8UAEmFo2cEJfpsZjyynkBsTnQ5rQVNgM7TbXXfboxwWwhg4HnWIcmlTs2YM1a9v+idK6LSfX9y/N
    vhf9pl0DQflc9ym4z/XCq87erCce+11kxH1+36N6rRqeiHVBYnoYIGMH690r4cgE8cW5B4eK7kaD
    3iCbmpChO0gZSa5Lex49WLXeFfM+ukd9y3AB00KMZcsUV5bCgwShH053ZQa+FMON8w==
    -----END CERTIFICATE-----

Example 2: Get a non-existent domain or one not running LDAP or DNS.


    $ python get_direct_certificate.py foo.example.com Y
    {
        "is_found": false, 
        "dns": {
            "status": 404, 
            "message": "Certificate not found.", 
            "is_found": false, 
            "details": "No DNS server found."
        }, 
        "ldap": {
            "status": 404, 
            "message": "No certificate found.", 
            "is_found": false, 
            "details": "No LDAP server found."
        }
    }

Example 3: Get a certificate via LDAP. Two are returned.

    $ get_direct_certificate.py d4@domain2.dcdt31prod.sitenv.org Y
    
    {
    "is_found": true, 
       "dns": {
            "status": 404, 
            "message": "The server did not provide an answer. No certificate found.", 
            "is_found": false
        }, 
        "ldap": {
             "status": 200, 
             "message": "certificate domain2.demo.direct-test.com found.", 
             "is_found": true
        }
    }

Example 3.1: Print out the contents of the certificate with openssl.
--------------------------------------------------------------------

(There are many tools for this purpose. Openssl is just an example.)

    $ openssl x509 -in d4@domain2.dcdt31prod.sitenv.org.pem -inform PEM -noout -text

    Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number: 1535297520576733558 (0x154e78f5ea83a176)
    Signature Algorithm: sha1WithRSAEncryption
        Issuer: CN=demo.direct-test.com_ca
        .
        .
        .



Microservice
============

The microservice is designed to facilitate real-time validation of direct addresses.
Provide an IP address or hostname, and a port number to start the service.  For example:


    python ./getdc_microservice.py localhost 8888


You can test it out with and web client.  For example, using curl


    curl http://localhost:8888/foo@example.com


Responds with:


   {
  "endpoint": "foo@example.com", 
  "valid_email": true, 
  "direct_address": false
   }



Python Library
-------------

The DCert class defines six functions; 3 get functions and 3 validate functions. 
The get functions are `get_certificate_dns`, `get_certificate_ldap`, and
`get_certificate`
both download certificates and return them to stdout.  `get_certificate` performs both
`get_certificate_dns` and `get_certificate_ldap` functions.

The verify functions are `validate_certificate_dns`, `validate_certificate_ldap`, and
`validate_certificate`. These functions return the JSON status document described above.
The `validate_certificate` function performs the actions of both
`validate_certificate_dns` and `validate_certificate_ldap`.


Below is an example of verify_certificate: 


    >>> from gdc.get_direct_certificate import DCert
    >>> import json
    >>>  d = DCert("ett.healthit.gov")
    >>> result = d.verify_certificate()
    >>> result['is_found']
    >>> True   # A certificate was found by at least one of the methods
    >>> json_result  = json.dumps(result, indent=4)
