from BaseHTTPServer import BaseHTTPRequestHandler
import json
from validate_email import validate_email
from collections import OrderedDict
from get_direct_certificate import DCert

__author__ = "Alan Viars"

PORT = 8080
IP = "0.0.0.0"


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

        self.send_response(200)
        self.end_headers()
        self.wfile.write(json.dumps(response, indent=2))
        return


if __name__ == '__main__':
    from BaseHTTPServer import HTTPServer
    server = HTTPServer((IP, PORT), GetHandler)
    print('Starting server at http://%s:%s' % (IP, PORT))
    server.serve_forever()
