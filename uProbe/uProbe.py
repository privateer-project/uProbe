from attestationagent.attestationAgentManager import AttestationAgentManager
from http.server import BaseHTTPRequestHandler
from http.server import HTTPServer
import sys
from util.cryptoutils import get_logger

class BasicHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(404)
        self.send_header('Content-type', 'application/json')
        self.end_headers()
        self.wfile.write('Runtime attestation not yet supported')
    def do_POST(self):
        self.send_response(404)
        self.send_header('Content-type', 'application/json')
        self.end_headers()
        self.wfile.write('Runtime attestation not yet supported')
    

def main(argv):
    if len(argv) != 2:
        print(f'Error found {len(argv)} arguments. Usage: {argv[0]} <CONTAINER ID>')
        return 1

    try:
        containerId = argv[1]

        logger = get_logger(filename=f'uProbe_{containerId}.log')

        attestationAgentManager = AttestationAgentManager(containerId)
        attestationAgentManager.get_secure_launch_evidence()

        managerPort = 8080

        securityProbeServer = HTTPServer(('', managerPort), BasicHandler)
        logger.info(f'uProbe {containerId} is up and running... on port {managerPort}')
        securityProbeServer.serve_forever()
    except KeyboardInterrupt:
        logger.info('KeyboardInterrupt caught. Cleaning up...')
    securityProbeServer.server_close()
    return 0

if __name__ == "__main__":
    main(sys.argv)