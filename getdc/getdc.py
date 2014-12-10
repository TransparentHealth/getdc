#!/usr/bin/env python
# -*- coding: utf-8 -*-
# vim: ai ts=4 sts=4 et sw=4
# Written by Alan Viars
import json, sys
import dns.query
import base64
import dns.resolver



    
def get_certificate_dns(endpoint):
        response = {}
        try:
        
            answers = dns.resolver.query(endpoint, 'CERT')
            
            for rdata in answers:
                #print 'Host', dir(rdata)#, 'has preference'#, rdata.preference
                fn = "%s.pem" % (endpoint)
                fh = open(fn, "w") 
                fh.writelines("-----BEGIN CERTIFICATE-----\n")
                fh.writelines(base64.encodestring(rdata.certificate).rstrip())
                fh.writelines("\n-----END CERTIFICATE-----\n")
                fh.close()
            response = {"status": 200, "message": "Certificate found."}
                
        except dns.resolver.NXDOMAIN:
            response = {"status": 404, "message": "Certificate not found."}
        
        
        except dns.resolver.NoNameservers:
            response = {"status": 412, "message": "Network failure."}
        
        
        
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
        result = get_certificate_dns(endpoint)
        print json.dumps(result, indent=4)

