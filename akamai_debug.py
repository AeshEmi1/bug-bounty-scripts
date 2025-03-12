#!/usr/bin/python3
import argparse
import sys
import requests
from requests.adapters import HTTPAdapter
import subprocess
from concurrent.futures import ProcessPoolExecutor
import socket

parser = argparse.ArgumentParser(
    prog='akamai_debug.py',
    description='Returns Akamai Debug information'
)
# Takes filename as a required positional argument
parser.add_argument('filename_in')
parser.add_argument('filename_out')
parser.add_argument('--akamai-out', help="Saves valid akamai domains to a file")
parser.add_argument('-b', '--brute-force', action="store_true", help="Brute forces unresolved domains against valid edgekey domains.")
args = parser.parse_args()
if args.akamai_out:
    valid_akamai_domains_file = parser.akamai_out
else:
    valid_akamai_domains_file = "valid_akamai_domains.txt"

valid_akamai_domains = set()
unresolved_domains = set() # Domains that failed to resolve
dns_results: dict = {} # Dictionary of CNAMEs
# my_resolver = Resolver()
# my_resolver.nameservers = ['8.8.8.8', '1.1.1.1', '9.9.9.9']
error_file = open("error_domains.txt", "w+")


class FrontingAdapter(HTTPAdapter):
    """"Transport adapter" that allows us to use SSLv3."""

    def __init__(self, fronted_domain=None, **kwargs):
        self.fronted_domain = fronted_domain
        super(FrontingAdapter, self).__init__(**kwargs)

    def send(self, request, **kwargs):
        connection_pool_kwargs = self.poolmanager.connection_pool_kw
        if self.fronted_domain:
            connection_pool_kwargs["assert_hostname"] = self.fronted_domain
        elif "assert_hostname" in connection_pool_kwargs:
            connection_pool_kwargs.pop("assert_hostname", None)
        return super(FrontingAdapter, self).send(request, **kwargs)

    def init_poolmanager(self, *args, **kwargs):
        server_hostname = None
        if self.fronted_domain:
            server_hostname = self.fronted_domain
        super(FrontingAdapter, self).init_poolmanager(server_hostname=server_hostname, *args, **kwargs)


def check_domain(hostname: str) -> bool:
    try:
        socket.setdefaulttimeout(2)
        socket.gethostbyname(hostname)
        return True
    except socket.error:
        return False


def name_resolution(domain, prod: bool) -> str|bool:
    """
    Returns the edgekey CNAME for a domain.
    """
    # Cache DNS queries
    if domain in dns_results.keys():
        cname: str = dns_results[domain]
    else:
        try:
            cname: str = subprocess.check_output(["dig", "+time=1", "+tries=2", domain, "CNAME", "+noall", "+short"]).decode('utf-8').lstrip().rstrip()
            dns_results[domain]: str = cname
        except:
            error_file.write(f"DIG failed for: {domain}\n")
            cname: str = "FAIL"
            dns_results[domain] = "FAIL"
            unresolved_domains.add(domain)
    if cname:
        # Check if CNAME is an akamai domain name
        if "edgekey-staging.net" in cname or "edgekey.net" in cname or "edgesuite.net" in cname or "edgesuite-staging.net" in cname:
            # If prod check that the domain is edgekey or staging, if not return a prod name
            if prod:
                if "edgekey.net" in cname or "edgesuite.net" in cname:
                    if cname[-1] == ".":
                        cname = cname[:-1]
                    valid_akamai_domains.add(cname)
                    return cname
                else:
                    cname = cname.replace("edgekey-staging.net", "edgekey.net")
                    cname = cname.replace("edgesuite-staging.net", "edgesuite.net")
                    if cname[-1] == ".":
                        cname = cname[:-1]
                    valid_akamai_domains.add(cname)
                    return cname
            else:
                if "edgekey-staging.net" in cname or "edgesuite-staging.net" in cname:
                    if cname[-1] == ".":
                        cname = cname[:-1]
                    valid_akamai_domains.add(cname)
                    return cname
                else:
                    cname = cname.replace("edgekey.net", "edgekey-staging.net")
                    cname = cname.replace("edgesuite.net", "edgesuite-staging.net")
                    if cname[-1] == ".":
                        cname = cname[:-1]
                    valid_akamai_domains.add(cname)
                    return cname
    else:
        if prod:
            if check_domain(f"{domain}.edgekey.net"):
                valid_akamai_domains.add(f"{domain}.edgekey.net")
                return f"{domain}.edgekey.net"
            if check_domain(f"{domain}.edgesuite.net"):
                valid_akamai_domains.add(f"{domain}.edgesuite.net")
                return f"{domain}.edgesuite.net"
        else:
            if check_domain(f"{domain}.edgekey-staging.net"):
                valid_akamai_domains.add(f"{domain}.edgekey-staging.net")
                return f"{domain}.edgekey-staging.net"
            elif check_domain(f"{domain}.edgesuite-staging.net"):
                valid_akamai_domains.add(f"{domain}.edgesuite-staging.net")
                return f"{domain}.edgesuite-staging.net"
        
        # Test the actual domain without akamai stuff
        if cname != "FAIL" and check_domain(domain):
            unresolved_domains.add(domain)
            return domain
        unresolved_domains.add(domain)
        return False


def create_session(domain: str) -> requests.Session:
    session = requests.Session()
    # session.mount('https://', FrontingAdapter(fronted_domain=domain))
    session.headers = {
        "Host": domain,
        "Pragma": "akamai-x-get-client-ip, akamai-x-cache-on, akamai-x-cache-remote-on, akamai-x-check-cacheable, akamai-x-get-cache-key, akamai-x-get-extracted-values, akamai-x-get-nonces, akamai-x-get-ssl-client-session-id, akamai-x-get-true-cache-key, akamai-x-serial-no, akamai-x-feo-trace, akamai-x-get-request-id, akamai-x-get-client-ip, akamai-x-ro-trace",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:126.0) Gecko/20100101 Firefox/126.1"
    }
    # session.verify = False
    session.allow_redirects = False
    return session


def parse_response(headers, domain: str, akamai_cdn_route: str) -> tuple:
    """
    Returns a parsed string of headers
    """
    response_str = ""
    akamai_debug_headers_present = True
    if headers is False:
        #return f"[{domain}] Domain does not exist, unable to perform request...\n"
        akamai_debug_headers_present = False
        return (response_str, akamai_debug_headers_present)
    if headers is None:
        akamai_debug_headers_present = False
        return (f"[{domain}] Domain exists, but unable to perform request...\n", akamai_debug_headers_present)
    # if domain_fronting:
    #     head = f"[{domain} via {akamai_cdn_route}]"
    # else:
    head = f"[{domain} via {akamai_cdn_route} - via HTTP]"
    if "X-Cache-Key" in headers:
        response_str = f"{response_str}{head} X-Cache-Key: {headers["X-Cache-Key"]}\n"
    if "X-True-Cache-Key" in headers:
        response_str = f"{response_str}{head} X-True-Cache-Key: {headers["X-True-Cache-Key"]}\n"
    if "X-Cache-Key-Extended-Internal-Use-Only" in headers:
        response_str = f"{response_str}{head} X-Cache-Key-Extended-Internal-Use-Only: {headers["X-Cache-Key-Extended-Internal-Use-Only"]}\n"
    if "X-Akamai-Session-Info" in headers:
        parsed_session_info = ""
        session_info_data = headers["X-Akamai-Session-Info"].split(", ")
        for session_info_pair in session_info_data:
            parsed_session_info = f"{parsed_session_info}{head} X-Akamai-Session-Info: {session_info_pair}\n"
        response_str = f"{response_str}{parsed_session_info}"
    if "X-Akamai-Pragma-Client-IP" in headers:
        response_str = f"{response_str}{head} X-Akamai-Pragma-Client-IP: {headers["X-Akamai-Pragma-Client-IP"]}\n"
    if not response_str:
        response_str = f"{head} Nothing Found.\n"
        akamai_debug_headers_present = False
    else:
        valid_akamai_domains.add(akamai_cdn_route)
    return (response_str+"\n\n", akamai_debug_headers_present)


output_file = open(args.filename_out, "w+")


with open(args.filename_in, "r") as akamai_domains:
    for akamai_domain in akamai_domains:
        akamai_domain = akamai_domain.lstrip().rstrip()
        print(f"Current Domain: {akamai_domain}")
        session = create_session(akamai_domain)
        akamai_cdn_name_prod = name_resolution(akamai_domain, True)
        akamai_cdn_name_staging = name_resolution(akamai_domain, False)

        # For checking without domain fronting later on
        headers = {
            "Host": akamai_domain,
            "Pragma": "akamai-x-get-client-ip, akamai-x-cache-on, akamai-x-cache-remote-on, akamai-x-check-cacheable, akamai-x-get-cache-key, akamai-x-get-extracted-values, akamai-x-get-nonces, akamai-x-get-ssl-client-session-id, akamai-x-get-true-cache-key, akamai-x-serial-no, akamai-x-feo-trace, akamai-x-get-request-id, akamai-x-get-client-ip, akamai-x-ro-trace"
        }

        # Prod
        if not akamai_cdn_name_prod:
            output_file.write(parse_response(False, akamai_domain, akamai_cdn_name_prod)[0])
        else:
            try:
                response = session.get(f"http://{akamai_cdn_name_prod}", timeout=5, allow_redirects=False)
                output_file.write(parse_response(response.headers, akamai_domain, akamai_cdn_name_prod)[0])
            except Exception as e:
                error_file.write(f"[{akamai_domain} via {akamai_cdn_name_prod}] - {e}\n")
                pass
        # Staging
        if not akamai_cdn_name_staging:
            output_file.write(parse_response(False, akamai_domain, akamai_cdn_name_staging)[0])
        elif akamai_cdn_name_prod == akamai_cdn_name_staging:
            # Do nothing for when we use the regular domain (the cdn prod name and cdn staging name will be the same)
            pass
        else:
            try:
                response = session.get(f"http://{akamai_cdn_name_staging}", timeout=5, allow_redirects=False)
                output_file.write(parse_response(response.headers, akamai_domain, akamai_cdn_name_staging)[0])
            except Exception as e:
                error_file.write(f"[{akamai_domain} via {akamai_cdn_name_staging}] - {e}\n")
                pass


with open (valid_akamai_domains_file, "w+") as valid_domain_file:
    for domain in valid_akamai_domains:
        valid_domain_file.write(domain+"\n")

if args.brute_force:
    for unresolved_domain in unresolved_domains:
        for valid_akamai_domain in valid_akamai_domains:
            session = create_session(unresolved_domain)
            response = session.get(f"http://{valid_akamai_domain}", timeout=5, allow_redirects=False)
            parsed_response = parse_response(response.headers, unresolved_domain, valid_akamai_domain)
            if not parsed_response[1]:
                continue
            print(parsed_response[0])
            output_file.write(parsed_response[0])
            break

error_file.close()
output_file.close()
