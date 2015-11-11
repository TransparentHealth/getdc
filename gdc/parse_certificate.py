#!/usr/bin/env python
# -*- coding: utf-8 -*-
# vim: ai ts=4 sts=4 et sw=4
# Written by Alan Viars, Josh Mandel
import requests
import json, sys
from  OpenSSL import crypto
from collections import OrderedDict


def open_cert(file_name, crypt_filetype=crypto.FILETYPE_PEM):
    f = open(file_name, 'r')
    cert_string = f.read()
    f.close()
    x509 = crypto.load_certificate(crypt_filetype, cert_string)
    return x509
    
    
def parsex509(x509):
    cert_detail =OrderedDict()
    cert_detail['no_aia'] = False
    cert_detail['no_crl'] = False
    cert_detail['subject'] =  dict(x509.get_subject().get_components())
    
    if x509.has_expired():
        cert_detail["is_expired"] = True    
    else:
        cert_detail["is_expired"]  = False
    
    cert_detail['serial_number'] =  x509.get_serial_number()
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
    return cert_detail



def enchalada(x509):
    
    #build the chain
    cert_detail = build_chain(x509)
    return cert_detail
    


def build_chain(x509):
    #first link in the chain
    flat_chain = []
    
    cert_detail = parsex509(x509)
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
    
    return cert_detail


def verify_chain(chain):   
    results = OrderedDict()
    results["valid_chain"] = False
    id_keys = []
    for l in chain:
        link= OrderedDict()
        subjectKeyIdentifier = l['extensions']['subjectKeyIdentifier']
        link['subjectKeyIdentifier']= l['extensions']['subjectKeyIdentifier']
        link['authorityKeyIdentifierkeyid']= l['extensions']['authorityKeyIdentifierkeyid']
        link['CN']= l['subject']['CN']
        id_keys.append(link)
    
    keymatch = []
    for i in range(0, len(id_keys)):
     
        try:
            if id_keys[i]['authorityKeyIdentifierkeyid'] == id_keys[i+1]['subjectKeyIdentifier']:
                keymatch.append(id_keys[i]['CN'])
        except:
            if id_keys[i]['authorityKeyIdentifierkeyid'] == id_keys[i]['authorityKeyIdentifierkeyid']:
                k = "%s[Assumed Root]" % (id_keys[i]['CN'])
                keymatch.append(id_keys[i]['CN'])
       
        #print "Link", subjectKeyIdentifier
        #for i in range(0, len(results))
    if len(keymatch) == len(chain):
       results["valid_chain"] = True
   
    results["keyids"]=id_keys
    results["keymatch"]= keymatch
       
    return results
    
 
 
def validate_chain_link(cert_detail):
    aia = {}
    results ={}
    warnings =[]
    errors =[]
    ancestors = []
    
    if cert_detail['extensions'].has_key('authorityInfoAccessURIs'):
        for aia in cert_detail['extensions']['authorityInfoAccessURIs']:
            
            r = requests.get(aia)
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
           msg = "No AIAs found for %s" % (cert_detail['subject']['CN'])
           warnings.append(msg)
           
    #print "Get CRL Chain"
    #print "Compare"
    if warnings:
        results['warnings']=warnings
    if errors:
        results['errors']=errors
    if aia:
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
  
    cert_detail = build_chain(x509)
    
    print json.dumps(cert_detail, indent=4)
        
        
        
        
        
