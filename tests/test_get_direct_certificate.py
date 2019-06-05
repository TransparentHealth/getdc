import unittest
from gdc.get_direct_certificate import DCert

__author__ = "Alan Viars"

"""Please note the DNS test will fail if your ISP blocks large DNS responses.
This includes Time Warner Cable and Frontier Cable."""


class TestGetDirectCertificate(unittest.TestCase):

    def test_no_cert_found(self):
        endpoint = "direct.example.com"
        dc = DCert(endpoint)
        dc.validate_certificate(download_certificate=False)
        self.assertFalse(dc.result['is_found'])

    def test_dns_cert_found(self):
        endpoint = "ett.healthit.gov"
        dc = DCert(endpoint)
        dc.validate_certificate(download_certificate=False)
        self.assertTrue(dc.result['is_found'])
        self.assertTrue(dc.result['dns']['is_found'])

    def test_dns_email_bound_cert_found(self):
        endpoint = "no-aia@ett.healthit.gov"
        dc = DCert(endpoint)
        dc.validate_certificate(download_certificate=False)
        self.assertTrue(dc.result['is_found'])
        self.assertTrue(dc.result['dns']['is_found'])

    def test_ldap_cert_found(self):
        endpoint = "d4@domain2.dcdt31prod.sitenv.org"
        dc = DCert(endpoint)
        dc.validate_certificate(download_certificate=False)
        self.assertTrue(dc.result['ldap']['is_found'])

if __name__ == '__main__':
    unittest.main()
