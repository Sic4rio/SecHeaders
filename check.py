import sys
import ssl
import http.client
import urllib.request
import urllib.error
import socket
import json
from optparse import OptionParser
from tabulate import tabulate


class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


class SecurityHeadersChecker:
    def __init__(self):
        self.sec_headers = [
            'X-Content-Type-Options',
            'Content-Security-Policy',
            'X-Permitted-Cross-Domain-Policies',
            'Referrer-Policy',
            'Expect-CT',
            'Permissions-Policy',
            'Cross-Origin-Embedder-Policy',
            'Cross-Origin-Resource-Policy',
            'Cross-Origin-Opener-Policy',
            'X-XSS-Protection',
            'X-Frame-Options',
            'Strict-Transport-Security'
        ]
        self.headers = {}
        self.proxy = None
        self.ssldisabled = False
        self.json_output = False
        self.targetfile = None

    def log(self, message):
        sys.stdout.write(f'{message}\n')
        sys.stdout.flush()

    def normalize(self, target):
        if not target.startswith('http://') and not target.startswith('https://'):
            target = f'http://{target}'
        return target

    def build_opener(self, proxy, ssldisabled):
        opener = urllib.request.build_opener()
        if proxy:
            opener.add_handler(urllib.request.ProxyHandler({'http': proxy, 'https': proxy}))
        if ssldisabled:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            opener.add_handler(urllib.request.HTTPSHandler(context=context))
        urllib.request.install_opener(opener)

    def parse_headers(self, headers):
        self.headers = {k.lower(): v for k, v in headers}

    def print_error(self, target, e):
        sys.stdout = sys.__stdout__
        if isinstance(e, urllib.error.HTTPError):
            self.log(f'{Colors.FAIL}HTTPError: {e.code} {e.reason} - {target}{Colors.ENDC}')
        elif isinstance(e, urllib.error.URLError):
            self.log(f'{Colors.FAIL}URLError: {str(e.reason)} - {target}{Colors.ENDC}')
        elif isinstance(e, http.client.BadStatusLine):
            self.log(f'{Colors.FAIL}BadStatusLine: {str(e)} - {target}{Colors.ENDC}')
        elif isinstance(e, ssl.SSLError):
            self.log(f'{Colors.FAIL}SSLError: {str(e)} - {target}{Colors.ENDC}')
        else:
            self.log(f'{Colors.FAIL}Error: {str(e)} - {target}{Colors.ENDC}')

    def check_target(self, target):
        try:
            target = self.normalize(target)
            req = urllib.request.Request(target, headers=self.headers)
            response = urllib.request.urlopen(req, timeout=5)
            self.parse_headers(response.headers.items())
            response.close()
        except (urllib.error.HTTPError, urllib.error.URLError, http.client.BadStatusLine, ssl.SSLError) as e:
            self.print_error(target, e)
            return None
        except socket.timeout:
            self.log(f'{Colors.FAIL}Timeout - {target}{Colors.ENDC}')
            return None
        except socket.gaierror:
            self.log(f'{Colors.FAIL}Invalid URL - {target}{Colors.ENDC}')
            return None
        except Exception as e:
            self.log(f'{Colors.FAIL}Error: {str(e)} - {target}{Colors.ENDC}')
            return None
        return self.headers

    def report(self):
        found_headers = []
        missing_headers = []

        for header in self.sec_headers:
            header_value = self.headers.get(header.lower(), None)
            if header_value:
                found_headers.append((header, header_value))
            else:
                missing_headers.append(header)

        self.log(f'Security Headers')
        self.log(f'Found: {Colors.OKGREEN}{len(found_headers)}{Colors.ENDC}')
        self.log(tabulate(found_headers, headers=["Header", "Value"], tablefmt="pipe"))
        self.log(f'Missing: {Colors.FAIL}{len(missing_headers)}{Colors.ENDC}')
        self.log('\n'.join(missing_headers))
        self.log('')

    def main(self):
        parser = OptionParser()
        parser.add_option("-p", "--proxy", dest="proxy", help="Use a proxy server (e.g. http://proxy:8080)")
        parser.add_option("-d", "--disable-ssl", action="store_true", dest="ssldisabled",
                          help="Disable SSL/TLS certificate verification")
        parser.add_option("-j", "--json", action="store_true", dest="jsonoutput",
                          help="Output results in JSON format")
        parser.add_option("-f", "--file", dest="targetfile",
                          help="Load targets from file (one target per line)")
        (options, args) = parser.parse_args()

        self.proxy = options.proxy
        self.ssldisabled = options.ssldisabled
        self.json_output = options.jsonoutput
        self.targetfile = options.targetfile

        banner = r"""
   _____           __  __               __              
  / ___/___  _____/ / / /__  ____ _____/ /__  __________
  \__ \/ _ \/ ___/ /_/ / _ \/ __ `/ __  / _ \/ ___/ ___/
 ___/ /  __/ /__/ __  /  __/ /_/ / /_/ /  __/ /  (__  ) 
/____/\___/\___/_/ /_/\___/\__,_/\__,_/\___/_/  /____/  
	Security Header Check Sicario | 2023
                                                               
"""

        self.log(Colors.HEADER + banner + Colors.ENDC)

        if self.targetfile:
            if not os.path.isfile(self.targetfile):
                print(f'{Colors.FAIL}Target file not found: {self.targetfile}{Colors.ENDC}')
                sys.exit(1)

            with open(self.targetfile, 'r') as f:
                targets = [line.rstrip('\n') for line in f]

            for target in targets:
                self.log(f'Checking {target}')
                self.build_opener(self.proxy, self.ssldisabled)
                self.headers = self.check_target(target)
                if self.headers:
                    self.report()
                self.log('')
        else:
            target = input('Enter a target: ')
            self.build_opener(self.proxy, self.ssldisabled)
            self.headers = self.check_target(target)
            if self.headers:
                self.report()


if __name__ == "__main__":
    checker = SecurityHeadersChecker()
    checker.main()

