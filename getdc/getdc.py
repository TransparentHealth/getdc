#!/usr/bin/env python
# -*- coding: utf-8 -*-
# vim: ai ts=4 sts=4 et sw=4
# Written by Alan Viars, Josh Mandel

import json, sys
import dns.query
import base64
import dns.resolver
import ldap
from  OpenSSL import crypto
#from  OpenSSL import crypto
#if x509.has_expired():
#      print "expired"
#   else:
#      print "has expired."

#x509 = crypto.load_certificate(crypto.FILETYPE_PEM, cert)


def get_certificate(endpoint, save_to_disk= False, file_extension="pem"):
    response = ""
    if endpoint.__contains__("@"):
        email_endpoint = True
        email_username, email_domain = endpoint.split("@", 1)
    else:
        email_endpoint = False
    
    if email_endpoint:
        email_domain_bound_dns  = get_certificate_dns(email_domain, save_to_disk, file_extension)
        email_domain_bound_ldap = get_certificate_ldap(email_domain, save_to_disk, file_extension)
      
    
        if email_domain_bound_dns.startswith("-----BEGIN CERTIFICATE-----"):
            response = response + email_domain_bound_dns
        
        elif email_domain_bound_ldap.startswith("-----BEGIN CERTIFICATE-----"):
            response = response + email_domain_bound_ldap
                         
        else:
            #Try it a 2nd way, and try to get the email-bound certificate.
            endpoint_email_bound_dns  = get_certificate_dns(endpoint, save_to_disk, file_extension)
            endpoint_email_bound_ldap = get_certificate_ldap(endpoint, save_to_disk, file_extension)
            if endpoint_email_bound_dns.startswith("-----BEGIN CERTIFICATE-----"):
                response = response + endpoint_email_bound_dns
                
            elif endpoint_email_bound_ldap.startswith("-----BEGIN CERTIFICATE-----"):
                response = response + endpoint_email_bound_ldap
            else:
                response = "No certificate was found via LDAP or DNS."
            
    else:
        # Appears to be domain only     
    
        dns_response  = get_certificate_dns(endpoint,  save_to_disk, file_extension)
        ldap_response = get_certificate_ldap(endpoint,  save_to_disk, file_extension)        
        
        if dns_response.startswith("-----BEGIN CERTIFICATE-----"):
            response = response + dns_response
        
        if ldap_response.startswith("-----BEGIN CERTIFICATE-----"):
            response = response + ldap_response

    if not response:
        response = "No certificate was found via LDAP or DNS."
    
    return response
   
   



def validate_certificate(endpoint, download_certificate=False):
    result = {} 
    if endpoint.__contains__("@"):
        email_endpoint = True
        email_username, email_domain = endpoint.split("@", 1)
    else:
        email_endpoint = False
    
    if email_endpoint:
        email_domain_bound_dns  = validate_certificate_dns(email_domain, download_certificate)
        email_domain_bound_ldap = validate_certificate_ldap(email_domain, download_certificate)
      
    
        if email_domain_bound_dns['is_found'] or email_domain_bound_ldap['is_found']:
            result['domain_bound_cert'] = True
            result['is_found']          = True
            result['dns']               = email_domain_bound_dns
            result['ldap']              = email_domain_bound_ldap
             
        else:
            #Try it a 2nd way, and try to get the email-bound certificate.
            endpoint_email_bound_dns  = validate_certificate_dns(endpoint, download_certificate)
            endpoint_email_bound_ldap = validate_certificate_ldap(endpoint, download_certificate)
            if endpoint_email_bound_dns['is_found'] or endpoint_email_bound_ldap['is_found']:
                result['email_bound_cert'] = True
                result['is_found']         = True
                result['dns']              = endpoint_email_bound_dns 
                result['ldap']             = endpoint_email_bound_ldap
            else:
                result['dns']               = email_domain_bound_dns
                result['ldap']              = email_domain_bound_ldap
                result['is_found']          = False
            
    else:
        # Appears to be domain only     
    
        result['dns']  = validate_certificate_dns(endpoint, download_certificate)
        result['ldap'] = validate_certificate_ldap(endpoint, download_certificate)        
        
        if result['dns']['is_found'] or result['ldap']['is_found']:
            result['is_found']=True
        else:
            result['is_found']=False
    return result    

    
def validate_certificate_dns(endpoint, download_certificate=False, response={"is_found":False}):
        
        endpoint =  endpoint.replace("@", ".")
        
        try:
            answers = dns.resolver.query(endpoint, 'CERT')
            i=1
            cert_list = []
            for rdata in answers:
                if download_certificate:
                    if i > 1:
                        fn = "%s_%s.pem" % (endpoint, i)
                    else:
                        fn = "%s.pem" % (endpoint)
                    fh = open(fn, "w") 
                    fh.writelines("-----BEGIN CERTIFICATE-----\n")
                    fh.writelines(base64.encodestring(rdata.certificate).rstrip())
                    fh.writelines("\n-----END CERTIFICATE-----\n")
                    fh.close()
                    
                #Create a cert object so we can inspect it for more details
                cert_string = "-----BEGIN CERTIFICATE-----\n" +\
                              base64.encodestring(rdata.certificate).rstrip() +\
                              "\n-----END CERTIFICATE-----\n"
                x509 = crypto.load_certificate(crypto.FILETYPE_PEM, cert_string)
                
                #Is the cert expired ?
                if x509.has_expired():
                    cert_detail = {"is_expired": True}    
                else:
                    cert_detail = {"is_expired": False}
                #Add it to the list (we use a list beacuse there can be more than one.)
                cert_list.append(cert_detail)    
            msg = "The certificate %s was found." % (endpoint)
            response.update({"status": 200, "message": msg,
                             "is_found": True, "cert_details": cert_list})
                
        except dns.resolver.NXDOMAIN:
            response.update({"status": 404, "message": "Certificate not found.",
                             "details" : "No DNS server found."})
        
        except dns.resolver.NoNameservers:
            response.update({"status": 412, "message": "No Name Servers. Network failure. No certificate found.",
                        "details": "You may be disconnected from the Internet. If you have an Internet connection then a certificate may exist, but or your intetrnet service provider (ISP) blocks large DNS requests. Many ISPs do this block including Time Warner Cable and Frontier Cable."
                        })
            
        except dns.resolver.NoAnswer:
            response.update({"status": 404, "message": "No Answer.",
                             "details":"The server did not provide an answer. No certificate found."})
        
        except dns.exception.Timeout:
             response.update({"status": 500, "message": "Timeout",
                "details": "The certifcate may exist but or your intetrnet service provider (ISP) blocks large DNS requests. Many ISPs do this block including Time Warner Cable and Frontier Cable."})
        return response   
            
def validate_certificate_ldap(endpoint, download_certificate=False, response={"is_found":False}):
    error = False
    endpoint =  endpoint.replace("@", ".")   
    
    try:
        ldap_servers = dns.resolver.query("_ldap._tcp."+endpoint, 'SRV').response.answer[0].items
        error=False
    except dns.resolver.NoNameservers:
        response.update({"status": 412, "message": "Network failure. "
                    "details" "You appear to be disconnected from the Internet.",
                    "is_found":False })
        error=True

    except dns.resolver.NXDOMAIN:
        response.update({"status": 404, "message": "No certificate found.",
                    "details" : "No LDAP server was found.","is_found":False  })
        error=True

    except dns.resolver.NoAnswer:
        response.update( {"status": 404, "message": "No certificate found.",
                    "details" :"The server did not provide an answer.",
                    "is_found":False })
        error=True
   
    if error:
        return response
        
        
    servers = [{
       'port': s.port, 
       'priority': s.priority,
       'host': s.target.to_text()
       } for s in ldap_servers]
        
    ldap_results = []
        
    for s in servers:
        url = "ldap://%(host)s:%(port)s"%s
        l = ldap.initialize(url)
        result_id  = l.search("", ldap.SCOPE_SUBTREE, "mail=%s"%endpoint, None)
        while True:
            rtype, rdata = l.result(result_id, 0)
            if rdata == []: break
            ldap_results.append((rtype, rdata))

    # Only take valid results
    ldap_results = filter(lambda r: r[0] == 100, ldap_results)

    # Extract binary (DER) certs from responses
    cert_ders = ["".join(r[1][0][1]['userCertificate']) for r in ldap_results]      
    i = 1
    cert_list = []
    for c in cert_ders:
        if download_certificate:
            if i > 1:
                fn = "%s_%s.pem" % (endpoint, i)
            else:
                fn = "%s.pem" % (endpoint)    
            
            fh = open(fn, "w") 
            fh.writelines("-----BEGIN CERTIFICATE-----\n")
            fh.writelines(base64.encodestring(c).rstrip())
            fh.writelines("\n-----END CERTIFICATE-----\n")
            fh.close()
        #Create a cert object so we can inspect it for more details
        cert_string = "-----BEGIN CERTIFICATE-----\n" +\
                      base64.encodestring(c).rstrip() +\
                      "\n-----END CERTIFICATE-----\n"
        x509 = crypto.load_certificate(crypto.FILETYPE_PEM, cert_string)
                
        #Is the cert expired ?
        if x509.has_expired():
            cert_detail = {"is_expired": True}    
        else:
            cert_detail = {"is_expired": False}
        #Add it to the list (we use a list beacuse there can be more than one.)
        cert_list.append(cert_detail)    
        
        i += 1
        

    msg = "The certificate %s was found." % (endpoint)
    
    response.update({"status": 200, "message": msg, "is_found": True,
                     "cert_details": cert_list})    
        
    return response   



def get_certificate_dns(endpoint,  save_to_disk= True, file_extension="pem"):
        response =""
        endpoint =  endpoint.replace("@", ".")
        
        try:
            answers = dns.resolver.query(endpoint, 'CERT')
            i=1
            for rdata in answers:
                if save_to_disk:
                    
                    if i > 1:
                        fn = "%s_%s.%s" % (endpoint, i, file_extension)
                    else:
                        fn = "%s.%s" % (endpoint, file_extension)
                    fh = open(fn, "w")
                    fh.writelines("-----BEGIN CERTIFICATE-----\n")
                    fh.writelines(base64.encodestring(rdata.certificate).rstrip())
                    fh.writelines("\n-----END CERTIFICATE-----\n")
                    fh.close()
                    i+=1
                response = response + "-----BEGIN CERTIFICATE-----\n" + \
                   base64.encodestring(rdata.certificate).rstrip() + \
                   "\n-----END CERTIFICATE-----\n"
            return response
                
        except dns.resolver.NXDOMAIN:
            response ="No DNS server found. No certificate found."
        
        except dns.resolver.NoNameservers:
            response = "No nameservers. Network failure. No certificate found. You may be disconnected from the Internet. If you have an Internet connection then a certificate may exist, but or your Intetrnet Service Provider (ISP) blocks large DNS requests. Many ISPs do this block including Time Warner Cable and Frontier Cable."    
            
        except dns.resolver.NoAnswer:
            response = "No Answer. The server did not provide an answer. No certificate found."
        
        except dns.exception.Timeout:
             response="Timeout. A certificate may exist, but or your Intetrnet service provider (ISP) blocks large DNS requests. Many ISPs do this block including Time Warner Cable and Frontier Cable."
        return response 



def get_certificate_ldap(endpoint, save_to_disk= True, file_extension="pem"):
    response =""
    endpoint =  endpoint.replace("@", ".")   
    
    try:
        ldap_servers = dns.resolver.query("_ldap._tcp."+endpoint, 'SRV').response.answer[0].items
        error=False
    except dns.resolver.NoNameservers:
        response ="Network failure. You appear to be disconnected from the Internet."
        error=True

    except dns.resolver.NXDOMAIN:
        response ="No certificate found. No LDAP server was found."
        error=True

    except dns.resolver.NoAnswer:
        response ="No certificate found. The server did not provide an answer."
        error=True
   
    if error:
        return response
        
        
    servers = [{
       'port': s.port, 
       'priority': s.priority,
       'host': s.target.to_text()
       } for s in ldap_servers]
        
    ldap_results = []
        
    for s in servers:
        url = "ldap://%(host)s:%(port)s"%s
        l = ldap.initialize(url)
        result_id  = l.search("", ldap.SCOPE_SUBTREE, "mail=%s"%endpoint, None)
        while True:
            rtype, rdata = l.result(result_id, 0)
            if rdata == []: break
            ldap_results.append((rtype, rdata))

    # Only take valid results
    ldap_results = filter(lambda r: r[0] == 100, ldap_results)

    # Extract binary (DER) certs from responses
    cert_ders = ["".join(r[1][0][1]['userCertificate']) for r in ldap_results]      
    i = 1
    
    for c in cert_ders:
        if  save_to_disk: 
            if i > 1:
                fn = "%s_%s.%s" % (endpoint, i, file_extension)
            else:
                fn = "%s.%s" % (endpoint, file_extension)    
          
            fh = open(fn, "w") 
            fh.writelines("-----BEGIN CERTIFICATE-----\n")
            fh.writelines(base64.encodestring(c).rstrip())
            fh.writelines("\n-----END CERTIFICATE-----\n")
            fh.close()
        response = response + "-----BEGIN CERTIFICATE-----\n" + \
                   base64.encodestring(c).rstrip() + \
                   "\n-----END CERTIFICATE-----\n"
        i += 1
        
    return response






if __name__ == "__main__": 
    
    #Get the file from the command line
    if len(sys.argv)<3:
        print "You must suppy an endpoint and indicate wheather or not you want to download the certificate."
        print "For example, jon@direct.example.com or direct.example.com"
        print "Usage: get_certificate_dns [email/endpoint] [Download_Certificate Y/N]"
        sys.exit(1)
    else:
        endpoint = sys.argv[1]
        if sys.argv[2] in ("Y", "y", "yes", "t", "T", "true", "True"):
            download_certificate = True
        else:
             download_certificate = False   
        
        result = validate_certificate(endpoint, download_certificate)
        print json.dumps(result, indent=4)

        
        
