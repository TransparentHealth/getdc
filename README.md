Get a Direct Certificate
========================

version 0.1

This tools is designed to simplify Direct certificate 
discovery and verification.

This library and command line utility attempts to fetch an x509 
certificate from DNS.  A JSON response indicates wheither the 
certificate was found or not is returned to stout. If found, the 
utility also saves the certificate as a .pem file in the local file system.

Command Line Utility
--------------------

    > python getdc.py hit-testing.nist.gov
    
    {
    "status": 200, 
    "message": "Certificate found."
    }

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

    > python getdc.py foo.example.com
    {
    "status": 404,
    "message": "Certificate not found."
    }

    > python getdc.py hit-testing.nist.gov
    {
    "status": 412,
    "message": "Network failure."
    }

Library
-------

The function `get_certificate_dns` performs the same function as the
command line utility.

    >>> from getdc import get_certificate_dns
    >>> result = get_certificate_dns("hit-testing.nist.gov")
    >>> print result
