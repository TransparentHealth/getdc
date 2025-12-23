#!/usr/bin/env python
# -*- coding: utf-8 -*-
import requests
import json
import sys
import os
from OpenSSL import crypto
from collections import OrderedDict
import argparse

class dummy_http_response(object):
    status_code = 0


def open_cert(file_name, crypt_filetype=crypto.FILETYPE_PEM):
    f = open(file_name, 'r')
    cert_string = f.read()
    f.close()
    x509 = crypto.load_certificate(crypt_filetype, cert_string)
    return x509


def parsex509(x509, expected_bound_entity=""):
    cert_detail = OrderedDict()

    if expected_bound_entity:
        cert_detail['bound_to_expected_entity'] = False

    serial_number = hex(x509.get_serial_number())[2:]
    if len(serial_number) % 2 != 0:
        serial_number = "0%s" % (serial_number)
    cert_detail['serial_number'] = serial_number.upper()

    cert_detail['subject'] = dict((k.decode('utf-8'), v.decode('utf-8')) for k, v in x509.get_subject().get_components())
    cert_detail["status"] = "ACTIVE"

    if x509.has_expired():
        cert_detail["is_expired"] = True
        cert_detail["status"] = "EXPIRED"
    else:
        cert_detail["is_expired"] = False

    cert_detail['aia_present'] = True
    cert_detail['crl_present'] = True

    cert_detail['issuer'] = dict((k.decode('utf-8'), v.decode('utf-8')) for k, v in x509.get_issuer().get_components())
    cert_detail['notBefore'] = x509.get_notBefore().decode('utf-8')
    cert_detail['notAfter'] = x509.get_notAfter().decode('utf-8')

    cert_detail['signature_algorithm'] = x509.get_signature_algorithm().decode('utf-8')
    cert_detail['version'] = x509.get_version()

    # Add the extensions ---------------------------------------
    extensions = OrderedDict()
    ext_count = x509.get_extension_count()

    # check for CRLs or AIAs by looking through extensions
    has_aia = False
    has_crl = False
    for i in range(ext_count):
        ext = x509.get_extension(i)
        name = ext.get_short_name()
        if isinstance(name, bytes):
            name = name.decode('utf-8')
        if name == "authorityInfoAccess":
            has_aia = True
        if name == "crlDistributionPoints":
            has_crl = True
    
    if not has_aia:
        cert_detail['aia_present'] = False
    if not has_crl:
        cert_detail['crl_present'] = False

    # process each extension
    for i in range(ext_count):
        e = x509.get_extension(i)

        name = e.get_short_name()
        try:
            value = e.__str__().rstrip()
        except crypto.Error:
            value = ""

        # if not in this list just take value as-is
        if name not in (
            "subjectAltName",
            "crlDistributionPoints",
            "authorityInfoAccess",
            "authorityKeyIdentifier",
            "keyUsage"):
            name_str = name.decode('utf-8') if isinstance(name, bytes) else name
            value_str = value.decode('utf-8') if isinstance(value, bytes) else value
            extensions[name_str] = value_str
        # otherwise we want to special parse

        elif name == "subjectAltName":
            try:
                santype, sanvalue = value.split(":")
                santypename = "%s%s" % (name.decode('utf-8') if isinstance(name, bytes) else name, santype)
                extensions[santypename] = sanvalue
            except ValueError:
                santypename = "%s%s" % (name.decode('utf-8') if isinstance(name, bytes) else name, "unk")
            extensions[santypename] = value
        elif name == "crlDistributionPoints":
            crl_values = []
            crl_uris = []
            u = []
            crl_values = value.split("\n")
            for cv in crl_values:
                if cv.__contains__("URI:"):
                    u = cv.split(":", 1)
                    crl_uris.append(u[1])
            crltypename = "%sURIs" % (name.decode('utf-8') if isinstance(name, bytes) else name)
            if not crl_uris:
            # Our list of CRLs is empty so flag
                cert_detail['crl_present'] = False
            extensions[crltypename] = crl_uris

        elif name == "authorityInfoAccess":
            aia_values = []
            aia_uris = []
            a = []
            aia_values = value.split("\n")
            for av in aia_values:
                if av.__contains__("URI:"):
                    a = av.split(":", 1)
                    aia_uris.append(a[1])
            aiatypename = "%sURIs" % (name.decode('utf-8') if isinstance(name, bytes) else name)
            if not aia_uris:
                # Our list of AIAs is empty so flag
                cert_detail['aia_present'] = False

            extensions[aiatypename] = aia_uris
        elif name == "authorityKeyIdentifier":
            akiname, akivalue = value.split(":", 1)
            akivalue = akivalue.split("\n", 1)

            akitypename = "%s%s" % (name.decode('utf-8') if isinstance(name, bytes) else name, akiname)
            extensions[akitypename] = akivalue[0]

        elif name == "keyUsage":
            usages = value.split(",")
            cusages = [u.rstrip().lstrip() for u in usages]
            extensions["keyUsage"] = cusages

    cert_detail['extensions'] = extensions
    if extensions.get("subjectAltNameemail", ""):
        dot_version = extensions.get(
            "subjectAltNameemail", "").replace("@", ".")
    elif extensions.get("subjectAltNameDNS", ""):
        dot_version = extensions.get("subjectAltNameDNS", "").replace("@", ".")
    else:
        dot_version = ""
    expected_bound_entry_dns_prefix = "DNS:%s" % (expected_bound_entity)
    if extensions.get("subjectAltName", "") == expected_bound_entry_dns_prefix:
        cert_detail['bound_to_expected_entity'] = True
    
    if extensions.get("subjectAltNameemail", "") == expected_bound_entity:
        cert_detail['bound_to_expected_entity'] = True
    if dot_version == expected_bound_entity:
        cert_detail['bound_to_expected_entity'] = True
    if extensions.get("subjectAltNameDNS", "") == expected_bound_entity:
        cert_detail['bound_to_expected_entity'] = True
    if dot_version == expected_bound_entity:
        cert_detail['bound_to_expected_entity'] = True

    if expected_bound_entity:
        dns_version = expected_bound_entity.replace("@", ".")
        if extensions.get("subjectAltNameemail", "") == dns_version:
            cert_detail['bound_to_expected_entity'] = True
        if extensions.get("subjectAltNameDNS", "") == dns_version:
            cert_detail['bound_to_expected_entity'] = True

    return cert_detail


def build_chain(x509, expected_bound_entity=""):
    # first link in the chain
    flat_chain = []

    cert_detail = parsex509(x509, expected_bound_entity)

    # cert_detail['chain'] = []
    # cert_detail['aia'] = validate_chain_link(cert_detail)
    # flat_chain.append(cert_detail)
    # cert_detail['chain'].append(cert_detail['aia'])

    # parent = cert_detail['aia']['aia']
    # flat_chain.append(parent)

    # while parent.get('aia_present', False) is True:
    #    parent = validate_chain_link(parent)
    #    cert_detail['chain'].append(parent['aia'])
    #    flat_chain.append(parent['aia'])
    #    parent = parent['aia']

    # cert_detail['chainVerification'] = verify_chain(flat_chain)
    # if cert_detail['chainVerification']['valid_chain']:
    #    cert_detail["chain_status"] = "IN-TACT"

    # cert_detail["revocation_status"] = cert_detail[
    #    'chainVerification']['revocation_status']

    
    return cert_detail


def verify_chain(chain):
    results = OrderedDict()
    results["valid_chain"] = False
    links = []
    revocation_status = "ACTIVE"

    for l in chain:
        link = OrderedDict()
        if 'extensions' in l:
            if 'subjectKeyIdentifier' in l['extensions'] and \
               'authorityKeyIdentifierkeyid' in l['extensions']:

                link['subjectKeyIdentifier'] = l[
                    'extensions']['subjectKeyIdentifier']
                link['authorityKeyIdentifierkeyid'] = l[
                    'extensions']['authorityKeyIdentifierkeyid']

                link['CN'] = l['subject'].get('CN')
                link['serial_number'] = l['serial_number']

            if 'crlDistributionPointsURIs' in l['extensions']:
                link['crlDistributionPointsURIs'] = l[
                    'extensions']['crlDistributionPointsURIs']

            links.append(link)

    keymatch = []

    # Check for subject key matching -----------------------------------------
    for i in range(0, len(links)):
        try:
            if links[i]['authorityKeyIdentifierkeyid'] == links[
                    i + 1]['subjectKeyIdentifier']:
                keymatch.append(links[i]['CN'])
        except:
            if links[i].get('authorityKeyIdentifierkeyid') == links[
                    i].get('authorityKeyIdentifierkeyid'):
                k = "%s[Assumed Root or Self-Signed]" % (links[i].get('CN'))
                keymatch.append(k)

    if len(keymatch) == len(chain) and len(keymatch) > 0:
        results["valid_chain"] = True

    # perform the CRL
    revocation = []
    for link in links:
        revocation.append(verify_not_revoked(link))

    results["revocation"] = revocation

    for r in revocation:
        if 'crl' in r:
            for c in r['crl']:
                if 'revoked' in c:
                    if c['revoked']:
                        revocation_status = "REVOKED"
        if r['crl_present'] is False:
            results["crl_present"] = False
            revocation_status = "UNDETERMINED"

    results["links"] = links
    results["keymatch"] = keymatch
    results["revocation_status"] = revocation_status

    return results


def verify_not_revoked(link):
    results = OrderedDict()
    errors = []
    warnings = []
    crl_list = []
    revoked = False

    if 'crlDistributionPointsURIs' in link:
        url_list = link['crlDistributionPointsURIs']
        for u in url_list:
            request_error = False
            crl_detail = OrderedDict()
            crl = None
            try:
                r = requests.get(u)
            except requests.exceptions.ConnectionError:
                msg = "ConnectionError: Could not fetch CRL %s" % (u)
                warnings.append(msg)
                request_error = True

            except requests.exceptions.Timeout:
                msg = "Timeout: Could not fetch CRL %s" % (u)
                warnings.append(msg)
                request_error = True

            except requests.exceptions.URLRequired:
                msg = "URLRequired: Could not fetch CRL %s" % (u)
                warnings.append(msg)
                request_error = True

            except requests.exceptions.RequestException:
                msg = "RequestException: Could not fetch CRL %s" % (u)
                warnings.append(msg)
                request_error = True

            except requests.exceptions.HTTPError:
                msg = "HTTPError: Could not fetch CRL %s" % (u)
                warnings.append(msg)
                request_error = True

            except requests.exceptions.TooManyRedirects:
                msg = "TooManyRedirects: Could not fetch CRL %s" % (u)
                warnings.append(msg)
                request_error = True

            if request_error:
                r = dummy_http_response()

            if r.status_code != 200:
                msg = "Could not fetch CRL %s" % (u)
                warnings.append(msg)
            else:
                # we got a response
                # try and parse it as pem

                try:
                    crl = crypto.load_crl(crypto.FILETYPE_PEM, r.text)
                except UnicodeEncodeError:
                    # Might be a der
                    try:
                        crl = crypto.load_crl(crypto.FILETYPE_ASN1, r.content)
                    except crypto.Error:
                        crl_detail["crl_present"] = False
                        msg = "Error parsing CRL URI %s" % (u)
                        errors.append(msg)

                except crypto.Error:
                    crl_detail["crl_present"] = False
                    msg = "Error parsing CRL URI %s" % (u)
                    errors.append(msg)
            if crl:

                crl_detail['crl_present'] = True
                # print "Parse the CRL", crl, u, "for serial ",
                # link['serial_number']
                crl_detail['serial_number'] = link['serial_number']

                # print "CRL Object loaded!!!!", crl.get_revoked()

                if crl.get_revoked():

                    for r in crl.get_revoked():
                        s = r.get_serial().upper()
                        if s == link["serial_number"]:
                            revoked = True

                if revoked:
                    crl_detail['revoked'] = True
                else:
                    crl_detail['revoked'] = False
                crl_list.append(crl_detail)

    else:
        msg = "No CRLs found for %s" % (link.get('CN'))
        warnings.append(msg)

    # print "Get CRL Chain"
    # print "Compare"
    if warnings:
        results['warnings'] = warnings
    if errors:
        results['errors'] = errors
    crl_present = False
    for c in crl_list:
        if c['crl_present'] is True:
            crl_present = True

    if crl_present:
        results['crl_present'] = True
        results['crl'] = crl_list
        results['CN'] = link.get('CN')
    else:
        results['crl_present'] = False
        results['crl'] = [{"crl_present": False,
                           "CN": link.get('CN'),
                           }, ]

    return results


def validate_chain_link(cert_detail):
    aia = OrderedDict()
    results = {}
    warnings = []
    errors = []

    if 'authorityInfoAccessURIs' in cert_detail['extensions']:
        for aia in cert_detail['extensions']['authorityInfoAccessURIs']:
            x509 = None
            request_error = False
            try:
                r = requests.get(aia)

            except requests.exceptions.ConnectionError:
                msg = "Connection Error: Could not fetch AIA %s" % (aia)
                warnings.append(msg)
                request_error = True

            except requests.exceptions.Timeout:
                msg = "Timeout: Could not fetch CRL"
                warnings.append(msg)
                request_error = True

            except requests.exceptions.URLRequired:
                msg = "URLRequired: Could not fetch CRL"
                warnings.append(msg)
                request_error = True

            except requests.exceptions.RequestException:
                msg = "RequestException: Could not fetch CRL"
                warnings.append(msg)
                request_error = True

            except requests.exceptions.HTTPError:
                msg = "HTTPError: Could not fetch CRL"
                warnings.append(msg)
                request_error = True

            except requests.exceptions.TooManyRedirects:
                msg = "TooManyRedirects: Could not fetch CRL"
                warnings.append(msg)
                request_error = True

            if request_error:
                r = dummy_http_response()

            if r.status_code != 200:
                msg = "Could not fetch AIA %s" % (aia)
                warnings.append(msg)
            else:
                # we got a response
                # try and pase it as pem
                x509 = None
                try:
                    x509 = crypto.load_certificate(crypto.FILETYPE_PEM, r.text)
                except UnicodeEncodeError:
                    # Might be a der
                    try:
                        x509 = crypto.load_certificate(
                            crypto.FILETYPE_ASN1, r.content)
                    except crypto.Error:
                        msg = "Error parsing presumed ASN1/DER URI %s" % (aia)
                        errors.append(msg)

                except crypto.Error:
                    msg = "Error parsing presumed PEM AIA URI %s" % (aia)
                    errors.append(msg)
            if x509:
                aia = parsex509(x509)
            else:
                aia = OrderedDict()
                # aia['aia_present'] = False
    else:    
        msg = "No AIAs found for %s" % (cert_detail['subject'].get('CN'))
        warnings.append(msg)
        aia = OrderedDict()
        # aia['aia_present'] = False

    if warnings:
        results['warnings'] = warnings
    if errors:
        results['errors'] = errors
    results['aia'] = aia

    return results


if __name__ == "__main__":



    parser = argparse.ArgumentParser(description='Inspect a Direct Secure Messaging certificate.')
    parser.add_argument(
        dest='filename',
        action='store',
        help='The local path to the PEM certificate file to inspect.')
    args = parser.parse_args()

    # # Get the file from the command line
    # if len(sys.argv) < 2:
    #     print("You must supply a PEM certificate.")
    #     print("Usage: parse_certificate.py [cert_file_name.pem]")
    #     sys.exit(1)

    file_name = args.filename

    x509 = open_cert(file_name)

    base = os.path.basename(file_name)
    # The expected bound entity (usually the common name)
    ebe = os.path.splitext(base)[0]

    cert_detail = build_chain(x509, ebe)
    # print "Done."
    print(json.dumps(cert_detail, indent=2))
