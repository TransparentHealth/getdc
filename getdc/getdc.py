#!/usr/bin/env python
# -*- coding: utf-8 -*-
# vim: ai ts=4 sts=4 et sw=4
# Written by Alan Viars, Josh Mandel

import json, sys
import dns.query
import base64
import dns.resolver
import ldap

def get_certificate(endpoint):
    result = {} 
    result['dns']  = get_certificate_dns(endpoint)
    result['ldap'] = get_certificate_ldap(endpoint)        
    
    if result['dns']['is_found'] or result['ldap']['is_found']:
        result['is_found']=True
    else:
        result['is_found']=False
    return result    

    
def get_certificate_dns(endpoint, response={"is_found":False}):
        endpoint =  endpoint.replace("@", ".")
        try:
        
            answers = dns.resolver.query(endpoint, 'CERT')
            for rdata in answers:
                
                fn = "%s_%s.pem" % (endpoint)
                
                fh = open(fn, "w") 
                fh.writelines("-----BEGIN CERTIFICATE-----\n")
                fh.writelines(base64.encodestring(rdata.certificate).rstrip())
                fh.writelines("\n-----END CERTIFICATE-----\n")
                fh.close()
            msg = "certificate %s found." % (endpoint)
            response.update({"status": 200, "message": msg})
                
        except dns.resolver.NXDOMAIN:
            response.update({"status": 404, "message": "Certificate not found.", "details" : "No DNS server found."})
        
        except dns.resolver.NoNameservers:
            response.update({"status": 412, "message": "Network failure. No certificate found.",
                        "details": "You may be disconnected from the Internet. If you have an Internet connection then it is likely that a certificate exists, but or your intetrnet service provider (ISP) blocks large DNS requests. Many ISPs do this block including Time Warner Cable and Frontier Cable."
                        })
            
        except dns.resolver.NoAnswer:
            response.update({"status": 404, "message": "The server did not provide an answer. No certificate found."})
            
        return response   
            
def get_certificate_ldap(endpoint, response={"is_found":False}):
    
    endpoint =  endpoint.replace("@", ".")   
    
    try:
        ldap_servers = dns.resolver.query("_ldap._tcp."+endpoint, 'SRV').response.answer[0].items
        
    except dns.resolver.NoNameservers:
        response.update({"status": 412, "message": "Network failure. "
                    "details" "You appear to be disconnected from the Internet.",})
        return response

    except dns.resolver.NXDOMAIN:
        response.update({"status": 404, "message": "No certificate found.",
                    "details" : "No LDAP server found." })
        return response

    except dns.resolver.NoAnswer:
        response.update( {"status": 404, "message": "No certificate found.",
                    "details" :"The server did not provide an answer."})
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
    
    
    print len(cert_ders)
    for c in cert_ders:
        
        if i > 1:
            fn = "%s_%s.pem" % (endpoint, i)
        else:
            fn = "%s.pem" % (endpoint)
            
        fh = open(fn, "w") 
        fh.writelines("-----BEGIN CERTIFICATE-----\n")
        fh.writelines(base64.encodestring(c).rstrip())
        fh.writelines("\n-----END CERTIFICATE-----\n")
        fh.close()
        i += 1

    msg = "certificate %s found." % (endpoint)
    is_found= True
    response.update({"status": 200, "message": msg, "is_found": is_found})    
        
    return response   

   
if __name__ == "__main__": 
    
    #Get the file from the command line
    if len(sys.argv)<2:
        print "You must suppy an email or endpoint."
        print "For example, jon@example.com or jon.example.com"
        print "Usage: get_certificate_dns [email/endpoint]"
        sys.exit(1)
    else:
        endpoint = sys.argv[1]
        result = get_certificate(endpoint)
        print json.dumps(result, indent=4)

