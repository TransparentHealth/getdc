#!/usr/bin/env python
# -*- coding: utf-8 -*-

import json
import sys
import base64
import dns.resolver
import ldap
from OpenSSL import crypto
from parse_certificate import build_chain
import argparse

class DCert:

    def __init__(self, endpoint,
                 download_certificate="N",
                 save_to_disk=True,
                 file_extension="pem",):

        self.endpoint = endpoint
        self.result = {}
        self.ldap_response = {}
        self.dns_response = {}

    def get_certificate(self, save_to_disk=False, file_extension="pem"):
        response = ""

        if self.endpoint.__contains__("@"):
            email_endpoint = True
            email_username, email_domain = self.endpoint.split("@", 1)
            self.original_endpoint = self.endpoint
            self.endpoint = email_domain
        else:
            email_endpoint = False

        if email_endpoint:
            email_domain_bound_dns = self.get_certificate_dns(save_to_disk,
                                                              file_extension)

            email_domain_bound_ldap = self.get_certificate_ldap(save_to_disk,
                                                                file_extension)

            if email_domain_bound_dns.startswith(
                    "-----BEGIN CERTIFICATE-----"):
                response = response + email_domain_bound_dns

            elif email_domain_bound_ldap.startswith("-----BEGIN CERTIFICATE-----"):
                response = response + email_domain_bound_ldap

            else:
                # Try it a 2nd way, and try to get the email-bound certificate.
                self.endpoint = self.original_endpoint
                endpoint_email_bound_dns = self.get_certificate_dns(
                    save_to_disk, file_extension)
                endpoint_email_bound_ldap = self.get_certificate_ldap(
                    save_to_disk, file_extension)
                if endpoint_email_bound_dns.startswith(
                        "-----BEGIN CERTIFICATE-----"):
                    response = response + endpoint_email_bound_dns
                elif endpoint_email_bound_ldap.startswith("-----BEGIN CERTIFICATE-----"):
                    response = response + endpoint_email_bound_ldap
                else:
                    response = "No certificate was found via LDAP or DNS."

        else:
            # Appears to be domain only

            dns_response = self.get_certificate_dns(
                save_to_disk, file_extension)
            ldap_response = self.get_certificate_ldap(
                save_to_disk, file_extension)

            if dns_response.startswith("-----BEGIN CERTIFICATE-----"):
                response = response + dns_response

            if ldap_response.startswith("-----BEGIN CERTIFICATE-----"):
                response = response + ldap_response
            else:
                self.ldap_response.update(
                    {'is_found': False, 'message': response})
                response = ""

        if not response:
            response = "No certificate was found via LDAP or DNS."

        return response

    def validate_certificate(self, download_certificate=False):

        result = {'is_found': False}

        # Check to see if there is an @ symbol to detect email;
        if self.endpoint.__contains__("@"):
            email_endpoint = True
            email_username, email_domain = self.endpoint.split("@", 1)
            self.email = self.endpoint
        else:
            # Its the domain only
            email_endpoint = False

        # If an email address was given
        if email_endpoint:
            # If an email address was given
            # First try the validation  against the domain part only
            self.endpoint = email_domain
            email_domain_bound_dns = self.validate_certificate_dns(
                download_certificate)
            email_domain_bound_ldap = self.validate_certificate_ldap(
                download_certificate)

            # Check to see if  we found any domain bound certificates
            if email_domain_bound_dns[
                    'is_found'] or email_domain_bound_ldap['is_found']:
                # Since we did, stop there and return the results
                result['domain_bound_cert'] = True
                result['is_found'] = True
                result['dns'] = email_domain_bound_dns
                result['ldap'] = email_domain_bound_ldap

            else:
                # Since no domain certs were found, try it a 2nd way.
                # Ty to get the email-bound certificate.
                self.endpoint = self.email
                endpoint_email_bound_dns = self.validate_certificate_dns(
                    download_certificate)
                endpoint_email_bound_ldap = self.validate_certificate_ldap(
                    download_certificate)
                if endpoint_email_bound_dns[
                        'is_found'] or endpoint_email_bound_ldap['is_found']:
                    result['email_bound_cert'] = True
                    result['is_found'] = True
                    result['dns'] = endpoint_email_bound_dns
                    result['ldap'] = endpoint_email_bound_ldap
                else:
                    result['dns'] = email_domain_bound_dns
                    result['ldap'] = email_domain_bound_ldap
                    result['is_found'] = False

        else:

            # Appears to be domain only
            result['dns'] = self.validate_certificate_dns(download_certificate)
            result['ldap'] = self.validate_certificate_ldap(
                download_certificate)

            if result['dns']['is_found'] or result['ldap']['is_found']:
                result['is_found'] = True
            else:
                result['is_found'] = False
        self.result = result
        return self.result

    def validate_certificate_dns(self, download_certificate=False):

        response = {"is_found": False}
        dns_cert_list = []
        self.endpoint = self.endpoint.replace("@", ".")

        try:
            answers = dns.resolver.resolve(self.endpoint, 'CERT')
            i = 1

            for rdata in answers:
                #print("rdata", rdata)
                if download_certificate:
                    if i > 1:
                        fn = "%s_%s.pem" % (self.endpoint, i)
                    else:
                        fn = "%s.pem" % (self.endpoint)
                    fh = open(fn, "w")
                    fh.writelines("-----BEGIN CERTIFICATE-----\n")
                    fh.writelines(base64.encodebytes(
                        rdata.certificate).rstrip().decode('utf8'))
                    fh.writelines("\n-----END CERTIFICATE-----\n")
                    fh.close()

                # Create a cert object so we can inspect it for more details
                cert_string = "-----BEGIN CERTIFICATE-----\n" +\
                              base64.encodebytes(rdata.certificate).rstrip().decode('utf-8') +\
                              "\n-----END CERTIFICATE-----\n"
                x509 = crypto.load_certificate(
                    crypto.FILETYPE_PEM, cert_string)

                cert_detail = build_chain(x509, self.endpoint)

                # Add it to the list (we use a list beacuse there can be more
                # than one.)
                dns_cert_list.append(cert_detail)
                i += 1
            msg = "One or more certificates for %s were found." % (self.endpoint)
            response.update({"status": 200, "message": msg,
                             "is_found": True, "cert_details": dns_cert_list})

        except dns.resolver.NXDOMAIN:
            response.update({"status": 404,
                             "message": "Certificate not found.",
                             "details": "No DNS server found."})

        except dns.resolver.NoNameservers:
            response.update(
                {
                    "status": 412,
                    "message": "No Name Servers. Network failure. No certificate found.",
                    "details": "You may be disconnected from the Internet. \
                                If you have an Internet connection then a certificate may exist, \
                                but or your Internet service provider (ISP) blocks large DNS requests. \
                                Many ISPs do this block including Time Warner Cable and Frontier Cable."})

        except dns.resolver.NoAnswer:
            response.update(
                {
                    "status": 404,
                    "message": "No Answer.",
                    "details": "The server did not provide an answer. No certificate found."})

        except dns.exception.Timeout:
            response.update(
                {
                    "status": 500,
                    "message": "Timeout",
                    "details": "The certifcate may exist but or your Internet service provider (ISP) blocks large DNS requests. \
                    Many ISPs do this block including Time Warner Cable and Frontier Cable."})
        self.dns_response = response
        return self.dns_response

    def validate_certificate_ldap(self, download_certificate):
        response = {"is_found": False}
        ldap_cert_list = []
        error = False
        self.endpoint = self.endpoint.replace("@", ".")

        try:
            ldap_servers = dns.resolver.resolve(
                "_ldap._tcp." + self.endpoint, 'SRV').response.answer[0].items
            error = False

        except dns.resolver.NoNameservers:
            response.update({"status": 412, "message": "Network failure. "
                             "details" "You appear to be disconnected from the Internet.",
                             "is_found": False})
            error = True

        except dns.resolver.NXDOMAIN:
            response.update({"status": 404, "message": "No certificate found.",
                             "details": "No LDAP server was found.", "is_found": False})
            error = True

        except dns.resolver.NoAnswer:
            response.update({"status": 404, "message": "No certificate found.",
                             "details": "The server did not provide an answer.",
                             "is_found": False})
            error = True

        except dns.resolver.LifetimeTimeout:
            response.update({"status": 500, "message": "Timeout",
                             "details": "The LDAP server was not found in DNS.",
                             "is_found": False})
            error = True
        
        except dns.resolver.Timeout:
            response.update({"status": 500, "message": "Timeout",
                             "details": "The LDAP server was not found in DNS.",
                             "is_found": False})
            error = True

        if error:
            return response

        try:
            servers = [{
                'port': s.port,
                'priority': s.priority,
                'host': s.target.to_text()
            } for s in ldap_servers]

            ldap_results = []

            for s in servers:
                url = "ldap://%(host)s:%(port)s" % s
                l = ldap.initialize(url)
                l.set_option(ldap.OPT_NETWORK_TIMEOUT, 10.0)

                result_id = l.search("", ldap.SCOPE_SUBTREE,
                                     "mail=%s" % self.endpoint, None)

                while True:
                    rtype, rdata = l.result(result_id, 0)
                    if rdata == []:
                        break
                    ldap_results.append((rtype, rdata))

            # Only take valid results
            ldap_results = filter(lambda r: r[0] == 100, ldap_results)

            # Extract binary (DER) certs from responses
            cert_ders = ["".join(r[1][0][1]['userCertificate'])
                         for r in ldap_results]
            i = 1
            for c in cert_ders:
                if download_certificate:
                    if i > 1:
                        fn = "%s_%s.pem" % (self.endpoint, i)
                    else:
                        fn = "%s.pem" % (self.endpoint)

                    fh = open(fn, "w")
                    fh.writelines("-----BEGIN CERTIFICATE-----\n")
                    fh.writelines(base64.encodestring(c).rstrip())
                    fh.writelines("\n-----END CERTIFICATE-----\n")
                    fh.close()
                # Create a cert object so we can inspect it for more details
                cert_string = "-----BEGIN CERTIFICATE-----\n" +\
                              base64.encodestring(c).rstrip() +\
                              "\n-----END CERTIFICATE-----\n"
                x509 = crypto.load_certificate(
                    crypto.FILETYPE_PEM, cert_string)

                # Get all the goodies
                cert_detail = build_chain(x509, self.endpoint)

                # Add it to the list (we use a list beacuse there can be more than
                # one.)
                ldap_cert_list.append(cert_detail)

                i += 1

            msg = "The certificate %s was found." % (self.endpoint)

            response.update({"status": 200, "message": msg, "is_found": True,
                             "cert_details": ldap_cert_list})

        except ldap.SERVER_DOWN:
            result_id = 0
            response.update({"status": 404,
                             "message": "No certificate found.",
                             "details": "The server did not provide an answer.",
                             "is_found": False})
        except ldap.OPERATIONS_ERROR:
            result_id = 0
            response.update({"status": 404,
                             "message": "No certificate found.",
                             "details": "The server did not provide an answer.",
                             "is_found": False})

        return response

    def get_certificate_dns(self, save_to_disk=True, file_extension="pem"):
        response = ""
        endpoint = self.endpoint.replace("@", ".")
        try:
            answers = dns.resolver.query(endpoint, 'CERT')
            i = 1
            print("i--->",i)
            for rdata in answers:
                if save_to_disk:

                    if i >= 1:
                        fn = "%s_%s.%s" % (endpoint, i, file_extension)
                    else:
                        fn = "%s.%s" % (endpoint, file_extension)
                    fh = open(fn, "w")
                    fh.writelines("-----BEGIN CERTIFICATE-----\n")
                    fh.writelines(base64.encodestring(
                        rdata.certificate).rstrip())
                    fh.writelines("\n-----END CERTIFICATE-----\n")
                    fh.close()
                    i += 1
                response = response + "-----BEGIN CERTIFICATE-----\n" + \
                    base64.encodestring(rdata.certificate).rstrip() + \
                    "\n-----END CERTIFICATE-----\n"
            return response

        except dns.resolver.NXDOMAIN:
            response = "No DNS server found. No certificate found."

        except dns.resolver.NoNameservers:
            response = "No nameservers. Network failure. No certificate found. You may be disconnected from the Internet. \
                       If you have an Internet connection then a certificate may exist, but or your Internet Service \
                       Provider (ISP) blocks large DNS requests. Many ISPs do this block including Time Warner Cable \
                       and Frontier Cable."

        except dns.resolver.NoAnswer:
            response = "No Answer. The server did not provide an answer. No certificate was found."

        except dns.exception.Timeout:
            response = "Timeout. A certificate may exist, but or your Internet service provider (ISP) blocks large DNS requests. \
                       Many ISPs do this block including Time Warner Cable and Frontier Cable."

        return response

    def get_certificate_ldap(self, save_to_disk=True, file_extension="pem"):
        response = ""
        self.endpoint = self.endpoint.replace("@", ".")
        try:
            ldap_servers = dns.resolver.query(
                "_ldap._tcp." + self.endpoint, 'SRV').response.answer[0].items
            error = False
        except dns.resolver.NoNameservers:
            response = "Network failure. You appear to be disconnected from the Internet."
            error = True

        except dns.resolver.NXDOMAIN:
            response = "No certificate found. No LDAP server was found."
            error = True

        except dns.resolver.NoAnswer:
            response = "No certificate found. The server did not provide an answer."
            error = True

        if error:
            response = {"is_found": False}
            return response

        servers = [{
            'port': s.port,
            'priority': s.priority,
            'host': s.target.to_text()
        } for s in ldap_servers]

        ldap_results = []

        for s in servers:
            url = "ldap://%(host)s:%(port)s" % s
            l = ldap.initialize(url)
            result_id = l.search("", ldap.SCOPE_SUBTREE,
                                 "mail=%s" % self.endpoint, None)
            while True:
                rtype, rdata = l.result(result_id, 0)
                if rdata == []:
                    break
                ldap_results.append((rtype, rdata))

        # Only take valid results
        ldap_results = filter(lambda r: r[0] == 100, ldap_results)

        # Extract binary (DER) certs from responses
        cert_ders = ["".join(r[1][0][1]['userCertificate'])
                     for r in ldap_results]
        i = 1

        for c in cert_ders:
            if save_to_disk:
                print("saving cert to disk")
                fn = "%s.%s" % (self.endpoint, file_extension)
                fh = open(fn, "w")
                fh.writelines("-----BEGIN CERTIFICATE-----\n")
                fh.writelines(base64.encodebytes(c).rstrip())
                fh.writelines("\n-----END CERTIFICATE-----\n")
                fh.close()
            response = response + "-----BEGIN CERTIFICATE-----\n" + \
                base64.encodebytes(c).rstrip() + \
                "\n-----END CERTIFICATE-----\n"
            i += 1

        return response


if __name__ == "__main__":

    parser = argparse.ArgumentParser(description='Get a certificate in from DNS and/or a public LDAP.')
    parser.add_argument(
        dest='endpoint',
        action='store',
        help='The endpoint to lookup in DNS and LDAP.  This is either a domain or email.')
    parser.add_argument('-d', '--downloadcerts', action="store_true", help='Save the certs found to disk.')
    args = parser.parse_args()

    dc = DCert(args.endpoint)
    dc.validate_certificate(args.downloadcerts)

    print(json.dumps(dc.result, indent=2))
