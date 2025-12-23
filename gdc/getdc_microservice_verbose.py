#!/usr/bin/env python
# Written by Alan Viars
import json
import sys
from validate_email import validate_email
from collections import OrderedDict
from get_direct_certificate import DCert

if (sys.version_info >= (3, 0)):
    # Python 3 code in this block
    from http.server import BaseHTTPRequestHandler, HTTPServer

else:
    # Python 2 code in this block
    from BaseHTTPServer import BaseHTTPRequestHandler
    from BaseHTTPServer import HTTPServer


__author__ = "Alan Viars"


class GetHandler(BaseHTTPRequestHandler):

    def _set_headers(self):
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.end_headers()

    def do_GET(self):

        self._set_headers()
        # parsed_path = urlparse.urlparse(self.path)
        clean_path = self.path.replace("/", "")
        is_valid_email = validate_email(clean_path)

        response = OrderedDict()
        response['endpoint'] = clean_path
        response["valid_email"] = is_valid_email
        dc = DCert(response['endpoint'])
        dc.validate_certificate(False)
        response["direct_address"] = dc.result['is_found']
        response["details"] = dc.result
        # self.send_response(200)
        self.end_headers()
        j = json.dumps(response, indent=2).encode('utf8')
        self.wfile.write(j)
        return


if __name__ == '__main__':

    if len(sys.argv) != 3:
        print("You must supply a host/ip and a port.")
        print("Usage: python getdc_microservice.py [HOST-or-IP] [PORT]")
        print("Example: python getdc_microservice.py localhost 8888")
        sys.exit(1)
    else:
        IP = sys.argv[1]
        PORT = int(sys.argv[2])
        server = HTTPServer((IP, PORT), GetHandler)

        print('Starting Certificate Discovery server at http://%s:%s' % (IP, PORT))
        server.serve_forever()

    # Get the file from the command line
