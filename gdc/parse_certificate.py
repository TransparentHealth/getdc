#!/usr/bin/env python
# -*- coding: utf-8 -*-
# vim: ai ts=4 sts=4 et sw=4
# Written by Alan Viars, Josh Mandel
import requests
import json, sys, os
from  OpenSSL import crypto
from collections import OrderedDict


class dummy_http_response(object):
    status_code = 0
    

def open_cert(file_name, crypt_filetype=crypto.FILETYPE_PEM):
    f = open(file_name, 'r')
    cert_string = f.read()
    f.close()
    x509 = crypto.load_certificate(crypt_filetype, cert_string)
    return x509
    
    
def parsex509(x509, expected_bound_entity=None):
    cert_detail =OrderedDict()
    
    if expected_bound_entity:
        cert_detail['bound_to_expected_entity'] = False
    
    
    serial_number = hex(x509.get_serial_number())[2:]
    if len(serial_number) % 2 != 0:
        serial_number ="0%s" % (serial_number)
    cert_detail['serial_number'] =  serial_number.upper()    

    cert_detail['subject'] =  dict(x509.get_subject().get_components())
    cert_detail["status"] = "ACTIVE"
    cert_detail["revocation_status"] = "ACTIVE"
    cert_detail["chain_status"] = "BROKEN"
    
    if x509.has_expired():
        cert_detail["is_expired"] = True
        cert_detail["status"] = "EXPIRED"
    else:
        cert_detail["is_expired"]  = False
   
    cert_detail['no_aia'] = False
    cert_detail['no_crl'] = False 
    
    cert_detail['issuer'] =  dict(x509.get_issuer().get_components())
    cert_detail['notBefore'] =  x509.get_notBefore()
    cert_detail['notAfter'] =  x509.get_notAfter()
    
    cert_detail['signature_algorithm'] =  x509.get_signature_algorithm()
    cert_detail['version'] =  x509.get_version()

    
    #Add the extensions ---------------------------------------
    extensions = OrderedDict()
    ext_count = x509.get_extension_count()
    
    
    #check for CRLs or AIAs
    short_names = [x509.get_extension(i).get_short_name() for i in range(ext_count)]
    if "authorityInfoAccess" not in short_names:
        cert_detail['no_aia'] = True
    if "crlDistributionPoints" not in short_names:
        cert_detail['no_crl'] = True     
    
    #process each extension
    for i in range(ext_count):
        e = x509.get_extension(i)
            
        
        name = e.get_short_name()
        value = e.__str__().rstrip()
        
        # if not in this list just take value as-is
        if name not in ("subjectAltName", "crlDistributionPoints", "authorityInfoAccess",
                        "authorityKeyIdentifier", "keyUsage"):
            extensions[name] = value
        #otherwise we want to special parse 
        
        elif name == "subjectAltName":
            santype, sanvalue = value.split(":")
            santypename = "%s%s" % (name, santype)
            extensions[santypename] = sanvalue
        
        elif name == "crlDistributionPoints":
            crl_values = []
            crl_uris = []
            u = []
            crl_values = value.split("\n")
            for cv in crl_values:
                if cv.__contains__("URI:"):
                    u = cv.split(":", 1)                    
                    crl_uris.append(u[1])
            crltypename = "%sURIs" % (name)
            if not crl_uris:
                #Our list of CRLs is empty so flag
                cert_detail['no_crl'] = True 
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
            aiatypename = "%sURIs" % (name)
            if not aia_uris:
                #Our list of AIAs is empty so flag
                cert_detail['no_aia'] = True 
            
            extensions[aiatypename] = aia_uris
        elif name == "authorityKeyIdentifier":
            akiname,akivalue  = value.split(":",1)
            akivalue = akivalue.split("\n",1)                                
                                            
            akitypename = "%s%s" % (name,akiname )
            extensions[akitypename] = akivalue[0]
       
        elif name == "keyUsage":
            usages  = value.split(",")
            cusages = [ u.rstrip().lstrip() for u in usages]
            extensions["keyUsage"] = cusages
       
    cert_detail['extensions'] = extensions 
    
    
    if extensions.get("subjectAltNameemail","") == expected_bound_entity:
        cert_detail['bound_to_expected_entity'] =True
    if extensions.get("subjectAltNameDNS","") == expected_bound_entity:
        cert_detail['bound_to_expected_entity'] =True
    
    if expected_bound_entity:
        dns_version =  expected_bound_entity.replace("@", ".")
        if extensions.get("subjectAltNameemail","") == dns_version:
            cert_detail['bound_to_expected_entity'] =True
        if extensions.get("subjectAltNameDNS","") == dns_version:
            cert_detail['bound_to_expected_entity'] =True
        
    return cert_detail



def enchalada(x509):
    
    #build the chain
    cert_detail = build_chain(x509)
    return cert_detail
    


def build_chain(x509, expected_bound_entity=None):
    #first link in the chain
    flat_chain = []
    
    cert_detail = parsex509(x509, expected_bound_entity )
    
    
    
    
    cert_detail['chain'] = []
    cert_detail['aia'] = validate_chain_link(cert_detail)
    flat_chain.append(cert_detail)
    cert_detail['chain'].append(cert_detail['aia'])
    
    
    parent = cert_detail['aia']['aia']
    flat_chain.append(parent)


    while parent['no_aia'] == False:
       parent = validate_chain_link(parent)
       cert_detail['chain'].append(parent['aia'])
       flat_chain.append(parent['aia'])
       parent = parent['aia']

    
    
    cert_detail['chainVerification'] = verify_chain(flat_chain)
    if cert_detail['chainVerification']['valid_chain']:
        cert_detail["chain_status"] = "IN-TACT"

    cert_detail["revocation_status"] = cert_detail['chainVerification']['revocation_status']
    
    
    return cert_detail


def verify_chain(chain):   
    results = OrderedDict()
    results["valid_chain"] = False
    links = []
    revocation_status = "ACTIVE"
    crl_check_list =[]
    for l in chain:
        link= OrderedDict()
        if l.has_key('extensions'):
            if l['extensions'].has_key('subjectKeyIdentifier') and \
               l['extensions'].has_key('authorityKeyIdentifierkeyid'):
        
                subjectKeyIdentifier = l['extensions']['subjectKeyIdentifier']
                link['subjectKeyIdentifier']= l['extensions']['subjectKeyIdentifier']
                link['authorityKeyIdentifierkeyid']= l['extensions']['authorityKeyIdentifierkeyid']
                
                link['CN']= l['subject']['CN']
                link['serial_number']= l['serial_number']
                
            if l['extensions'].has_key('crlDistributionPointsURIs'):
                link['crlDistributionPointsURIs']= l['extensions']['crlDistributionPointsURIs']
                
                
            links.append(link)
    
    keymatch = []
    
    #Check for subject key matching -----------------------------------------
    for i in range(0, len(links)):
        try:
            if links[i]['authorityKeyIdentifierkeyid'] == links[i+1]['subjectKeyIdentifier']:
                keymatch.append(links[i]['CN'])
        except:
            if links[i]['authorityKeyIdentifierkeyid'] == links[i]['authorityKeyIdentifierkeyid']:
                k = "%s[Assumed Root or Self-Signed]" % (links[i]['CN'])
                keymatch.append(k)
       
    if len(keymatch) == len(chain) and len(keymatch) > 0:
       results["valid_chain"] = True
   
   #perform the CRL 
    revocation = []
    for link in links:
        revocation.append(verify_not_revoked(link))
    
    
   
    results["revocation"]=revocation
    
    for r in revocation:
        if r.has_key('crl'):
            for c in r['crl']:
                if c.has_key('revoked'):
                    if c['revoked'] == True:
                        revocation_status = "REVOKED"
        if r['no_crl']== True:
            results["no_crl"]=   True
            revocation_status = "UNDETERMINED"
        
    results["links"]=links
    results["keymatch"]= keymatch
    results["revocation_status"]=   revocation_status
    
    return results
    
def verify_not_revoked(link):
    results =OrderedDict()
    errors = []
    warnings=[]
    crl_list = []
    revoked = False
    
    
    if link.has_key('crlDistributionPointsURIs'): 
            url_list = link['crlDistributionPointsURIs']
            for u in url_list:
                request_error = False
                crl_detail = OrderedDict()
                crl = None
                try:
                    r = requests.get(u)    
                except requests.exceptions.ConnectionError:
                    msg = "ConnectionError: Could not fetch CRL %s" % (u )
                    warnings.append(msg)
                    request_error = True
                    
                except requests.exceptions.Timeout:
                    msg = "Timeout: Could not fetch CRL %s" % (u )
                    warnings.append(msg)
                    request_error = True

                except requests.exceptions.URLRequired:
                    msg = "URLRequired: Could not fetch CRL %s" % (u )
                    warnings.append(msg)
                    request_error = True

                except requests.exceptions.RequestException:
                    msg = "RequestException: Could not fetch CRL %s" % (u )
                    warnings.append(msg)
                    request_error = True

                except requests.exceptions.HTTPError:
                    msg = "HTTPError: Could not fetch CRL %s" % (u )
                    warnings.append(msg)
                    request_error = True

                except requests.exceptions.TooManyRedirects:
                    msg = "TooManyRedirects: Could not fetch CRL %s" % (u )
                    warnings.append(msg)
                    request_error = True
                
                if request_error:
                    r = dummy_http_response()
                    
                    
                if r.status_code != 200:
                    msg = "Could not fetch CRL %s" % (u)
                    warnings.append(msg)
                else:
                    #we got a response
                    # try and parse it as pem
                    
                    try:
                        crl = crypto.load_crl(crypto.FILETYPE_PEM, r.text)
                    except UnicodeEncodeError:
                        #Might be a der
                        try: 
                            crl = crypto.load_certificate(crypto.FILETYPE_ASN1, r.content)
                        except crypto.Error:
                            crl_detail["no_crl"] = True
                            msg = "Error parsing CRL URI %s" % (u)
                            errors.append(msg)
                            
                    except crypto.Error:
                        crl_detail["no_crl"] = True
                        msg = "Error parsing CRL URI %s" % (u)
                        errors.append(msg)
                if crl:
                    
                    crl_detail['no_crl'] = False
                    #print "Parse the CRL", crl, u, "for serial ", link['serial_number']
                    crl_detail['serial_number'] = link['serial_number']
                    
                    #print "CRL Object loaded!!!!", crl.get_revoked()
                    
                    
                    if crl.get_revoked():
                        
                        for r in crl.get_revoked():
                             s =r.get_serial().upper()
                             if s == link["serial_number"]:
                                 revoked = True
                        
                    if revoked == True:
                           crl_detail['revoked'] = True
                    else:
                           crl_detail['revoked'] = False
                    crl_list.append(crl_detail)

    else:
       msg = "No CRLs found for %s" % (link['CN'])
       warnings.append(msg)
           
    #print "Get CRL Chain"
    #print "Compare"
    if warnings:
        results['warnings']=warnings
    if errors:
        results['errors']=errors
    no_crl = True
    for c in crl_list:
        if c['no_crl']==False:
             no_crl = False

            
    if no_crl==False:
        results['no_crl'] = False
        results['crl']=crl_list
        results['CN'] = link['CN']
    else:
        results['no_crl'] = True
        results['crl']= [{"no_crl": True,
                         "CN": link['CN'],
                         },]
    
    return results
    
    
 
def validate_chain_link(cert_detail):
    aia = OrderedDict()
    results ={}
    warnings =[]
    errors =[]
    ancestors = []
    
    if cert_detail['extensions'].has_key('authorityInfoAccessURIs'):
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
                    msg = "Timeout: Could not fetch CRL %s" % (u )
                    warnings.append(msg)
                    request_error = True

            except requests.exceptions.URLRequired:
                    msg = "URLRequired: Could not fetch CRL %s" % (u )
                    warnings.append(msg)
                    request_error = True

            except requests.exceptions.RequestException:
                    msg = "RequestException: Could not fetch CRL %s" % (u )
                    warnings.append(msg)
                    request_error = True
            
            except requests.exceptions.HTTPError:
                    msg = "HTTPError: Could not fetch CRL %s" % (u )
                    warnings.append(msg)
                    request_error = True

            except requests.exceptions.TooManyRedirects:
                    msg = "TooManyRedirects: Could not fetch CRL %s" % (u )
                    warnings.append(msg)
                    request_error = True    
                
            if request_error:
                r = dummy_http_response()
            
            if r.status_code != 200:
                msg = "Could not fetch AIA %s" % (aia)
                warnings.append(msg)
            else:
                #we got a response
                # try and pase it as pem
                x509 = None
                try:
                    x509 = crypto.load_certificate(crypto.FILETYPE_PEM, r.text)
                except UnicodeEncodeError:
                    #Might be a der
                    try: 
                        x509 = crypto.load_certificate(crypto.FILETYPE_ASN1, r.content)
                    except crypto.Error:
                        msg = "Error parsing presumed ASN1/DER URI %s" % (aia)
                        errors.append(msg)
                        
                except crypto.Error:
                    msg = "Error parsing presumed PEM AIA URI %s" % (aia)
                    errors.append(msg)
            if x509:
                aia  = parsex509(x509)
            else:
                aia = OrderedDict()
                aia['no_aia'] = True   
    else:
           msg = "No AIAs found for %s" % (cert_detail['subject']['CN'])
           warnings.append(msg)
           aia = OrderedDict()
           aia['no_aia'] = True
           
    if warnings:
        results['warnings']=warnings
    if errors:
        results['errors']=errors    
    results['aia']=aia
    
    return results
    

if __name__ == "__main__": 
    
    #Get the file from the command line
    if len(sys.argv)<2:
        print "You must supply a PEM certificate."
        print "Usage: parse_certificate.py [cert_file_name.pem]"
        sys.exit(1)
    
    file_name = sys.argv[1]

    x509 = open_cert(file_name)

    
    base=os.path.basename(file_name)    
    #The expected bound entity (usually the common name)
    ebe = os.path.splitext(base)[0]
    
    cert_detail = build_chain(x509, ebe)
    #print "Done."
    print json.dumps(cert_detail, indent=4)
        
        
        
        
        
