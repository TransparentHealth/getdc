Get Direct Certificate - A Command Line Utility and API for Certificate Discovery
=================================================================================

Written By Alan Viars @aviars with contributions from Josh Mandel @JoshCMandel 

Version 0.9.8.4

The `getdc` tool is designed to simplify and automate Direct certificate
discovery, however, it can be used to fetch any x509 certificate from LDAP
or DNS.

The command line utility and API attempts to fetch an x509 
certificate, or certificates, from DNS and.or LDAP.  If found, the utility
saves the certificate, or certificates, as a `.pem` file in the local file
system. A top level boolean variable `is_found` contains the flag indicating
if the certificate was found or not.

If an email address is presented the tool will first attempt to look up and
return a domain bound certificate.  If that fails, the tool will attempt to
look up an email-bound certificate. The response will indicate wheather a
domain-bound or email-bound certificate was retrieved. For this feature to work,
use the "@" symbol in the endpoint and not the DNS representation.
(e.g. "john@direct.example.com" instead of "john.direct.example.com".


Installation
------------

You need to make sure you have the prerequisites for the application.
The following instructions are for Ubuntu.

    sudo apt-get install -y python-ldap python-dnspython python-openssl cryptography

...then you can install with pip

    sudo pip install getdc

...or to install from source or into a virtualenv (on Ubuntu):


    sudo apt-get install -y build-essential python-dev libldap2-dev libsasl2-dev libffi-dev libssl-dev 
    sudo pip install getdc



Command Line Utility
--------------------

A response is printed as JSON to stout indicating wheather the certificate was found or
not via LDAP or DNS.

Usage:
    
    
    getdc [email/endpoint] [download Certificate Y/N]

Example 1: Discover a certificate via DNS and download the certificate

    $ python getdc.py hit-testing.nist.gov Y
    
    {
        "is_found": true, 
        "dns": {
            "status": 200, 
            "cert_details": [
                {
                    "is_expired": false
                }
            ], 
            "message": "The certificate hit-testing.nist.gov was found.", 
            "is_found": true
        }, 
        "ldap": {
            "status": 404, 
            "message": "No certificate found.", 
            "is_found": false, 
            "details": "No LDAP server was found."
        }
    }

Example 1.1: Print out the resulting PEM certificate as text

    > cat hit-testing.nist.gov.pem
    -----BEGIN CERTIFICATE-----
    MIIEJTCCAw2gAwIBAgIBBjANBgkqhkiG9w0BAQsFADBsMQswCQYDVQQGEwJVUzELMAkGA1UECAwC
    TUQxFTATBgNVBAcMDEdhaXRoZXJzYnVyZzENMAsGA1UECgwETklTVDERMA8GA1UEAwwIbmlzdC5n
    b3YxFzAVBgkqhkiG9w0BCQEWCG5pc3QuZ292MB4XDTE0MDQwMjE0MDEyOFoXDTE2MDQwMTE0MDEy
    OFowgYQxCzAJBgNVBAYTAlVTMQswCQYDVQQIDAJNRDEVMBMGA1UEBwwMR2FpdGhlcnNidXJnMQ0w
    CwYDVQQKDAROSVNUMR0wGwYDVQQDDBRoaXQtdGVzdGluZy5uaXN0LmdvdjEjMCEGCSqGSIb3DQEJ
    ARYUaGl0LXRlc3RpbmcubmlzdC5nb3YwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDQ
    2Dhq3mH3zkl+8gmELWdVA5ZpPoSS0dyl0RuBt+UceP3w2fQHHOkSj92ZGjpSMWbrXtlsFa2daVGZ
    2EDjv5EpDTw55U7rSuD1S7scpmsYL7w3RhfFfhF2KLc63Z3v7EaVhp3Bora7kMJMSIlPrvIuQFTA
    zBy7Lbal9PiMPOuiPdrcon5OMDg7JOVBFyzq1bq0pm82q2PPPoXymHLXKfsBT0jjNtnKSFSJe12n
    2ibYqgk+T7XaRjaBCDyMkKfAkRI348zhFW7BgRnIUW+2hePQTleAYzci/AGSpbKrt5Ary9PDYCBC
    WHvbQdi9Cv7BGSCF+4xWPS9X9b9dE/wKX43RAgMBAAGjgbgwgbUwCQYDVR0TBAIwADAfBgNVHREE
    GDAWghRoaXQtdGVzdGluZy5uaXN0LmdvdjAdBgNVHQ4EFgQUi2D+g5UA4HxZB+1WQ3TKhE26cEUw
    HwYDVR0jBBgwFoAU2b5OviFqiWCvpYQPeeWHf/+8RF0wCwYDVR0PBAQDAgWgMDoGA1UdHwQzMDEw
    L6AtoCuGKWh0dHA6Ly9zYW1wbGVjYS5uaXN0Lmdvdi9jcmwvbmlzdC5nb3YuY3JsMA0GCSqGSIb3
    DQEBCwUAA4IBAQC1kG1vB0xMasYozmduZiqmM2lqYtXKw5t9pIBB+VqAweg7d29gQMF2/5c6ZKRZ
    FGdcWY04EOYIM88qitqEfgebe4eEX2NmyGreCJL/RH7Cl0ex5vbospL0uCO4NulRg/hFoOKOEkFD
    bL33Zj57kRvjK5WcvmtQe1rO/QuV5+n1+MGjy2+BPzPqXNqZRz8N8XSkKfLf0K3OlLHSItgCrvWo
    5JXGI0AZRVF4qxb6qgkywpRGu8LRs5qKQyzpJ91vZiLr/5ARhPsEKImEXb4VQqD8UgkeSxUHnyQV
    GneC5c7K3HW1/GmvYwTybLeDM+mnDzKD/6Nb2qXTUffHoTWtHF8M
    -----END CERTIFICATE---- 

Example 2: Get a non-existent domain or one not running LDAP or DNS.


    $ python getdc.py foo.example.com Y
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

Example 3: Get a certificate via LDAP.

    $ python getdc.py domain2.demo.direct-test.com Y
    
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

There are many tools for this purpose. Openssl is just an example.

    $ openssl x509 -in domain2.demo.direct-test.com.pem -inform PEM -noout -text

    Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number: 1535297520576733558 (0x154e78f5ea83a176)
    Signature Algorithm: sha1WithRSAEncryption
        Issuer: CN=demo.direct-test.com_ca
        .
        .
        .



Application Programming Interface (API) for Python`get_certificate_dns
--------------------------------------------------

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


    >>> from getdc.getdc import DCert
    >>> import json
    >>>  d = DCert("hit-testing.nist.gov")
    >>> result = d.verify_certificate()
    >>> result['is_found']
    >>> True   # A certificate was found by at least one of the methods
    >>> json_result  = json.dumps(result, indent=4)
