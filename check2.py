import sys
import ssl
import http.client
import urllib.request
import urllib.error
import socket
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
        opener.addheaders = [('Content-Type', 'application/json')]  # Add the Content-Type header
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
            self.headers['effective-url'] = response.geturl()  # Include the effective URL in the headers
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

    def report(self, html_output=False):
        found_headers = []
        missing_headers = []

        effective_url = self.headers.get("effective-url", "Unknown")
        for header in self.sec_headers:
            header_value = self.headers.get(header.lower(), None)
            if header_value:
                found_headers.append((header, header_value))
            else:
                missing_headers.append(header)

        self.log('')
        self.log('=' * 50)
        self.log(f'[*] Analyzing headers of {Colors.OKGREEN}{effective_url}{Colors.ENDC}')
        self.log(f'[*] Effective URL: {Colors.OKGREEN}{effective_url}{Colors.ENDC}')
        for header, value in found_headers:
            self.log(f'[*] Header {header} is present! (Value: {Colors.OKGREEN}{value}{Colors.ENDC})')
        for header in missing_headers:
            self.log(f'[!] Missing security header: {Colors.FAIL}{header}{Colors.ENDC}')
        self.log('-' * 50)
        self.log(f'[!] Headers analyzed for {Colors.OKGREEN}{effective_url}{Colors.ENDC}')
        self.log(f'[+] There are {Colors.OKGREEN}{len(found_headers)}{Colors.ENDC} security headers enforced')
        self.log(f'[-] There are {Colors.FAIL}{len(missing_headers)}{Colors.ENDC} security headers missing!')
        self.log('')

        if html_output:
            html_table = tabulate(found_headers, headers=['Header', 'Value'], tablefmt='html')
            html_content = f'''
            <html>
                <head>
                    <title>Security Headers Report</title>
                </head>
                <body>
                    <h1>Security Headers Report</h1>
                    <h2>Target: {effective_url}</h2>
                    <h3>Enforced Security Headers:</h3>
                    {html_table}
                    <h3>Missing Security Headers:</h3>
                    <ul>
            '''

            for header in missing_headers:
                html_content += f'<li>{header}</li>'

            html_content += '''
                    </ul>
                </body>
            </html>
            '''

            with open('security_report.html', 'w') as f:
                f.write(html_content)

    def main(self):
        banner = r"""
   _____           __  __               __              
  / ___/___  _____/ / / /__  ____ _____/ /__  __________
  \__ \/ _ \/ ___/ /_/ / _ \/ __ `/ __  / _ \/ ___/ ___/
 ___/ /  __/ /__/ __  /  __/ /_/ / /_/ /  __/ /  (__  ) 
/____/\___/\___/_/ /_/\___/\__,_/\__,_/\___/_/  /____/  
    Security Header Check Sicario | 2023
"""

        self.log(Colors.HEADER + banner + Colors.ENDC)

        if len(sys.argv) > 1 and sys.argv[1] == '-h':
            self.log('Usage: python script.py [target]')
            self.log('Options:')
            self.log('  -h       Display this help menu')
            self.log('  -o       Output findings to HTML file')
            return

        target = input('Enter a target: ')
        if target == '-h':
            self.log('Usage: python script.py [target]')
            self.log('Options:')
            self.log('  -h       Display this help menu')
            self.log('  -o       Output findings to HTML file')
            return

        if '-o' in sys.argv:
            self.json_output = True

        self.build_opener(self.proxy, self.ssldisabled)
        self.headers = self.check_target(target)
        if self.headers:
            self.report(html_output=self.json_output)


if __name__ == "__main__":
    checker = SecurityHeadersChecker()
    try:
        checker.main()
    except KeyboardInterrupt:
        checker.log('\nExiting...')
        sys.exit(0)
