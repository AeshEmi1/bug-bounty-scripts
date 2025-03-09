#!/usr/bin/python3
import argparse
import sys
import requests
from requests.adapters import HTTPAdapter
import dns.resolver
import socket

parser = argparse.ArgumentParser(
    prog='akamai_debug.py',
    description='Returns Akamai Debug Information'
)
# Takes filename as a required positional argument
parser.add_argument('filename_in')
parser.add_argument('filename_out')
args = parser.parse_args()

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
        socket.gethostbyname(hostname)
        return True
    except socket.error:
        return False

def name_resolution(domain, prod: bool) -> str:
    """
    Returns the edgekey domain for a domain.
    """
    try:
        cnames = dns.resolver.resolve(domain, "CNAME")
    except:
        if prod:
            if check_domain(f"{domain}.edgekey.net"):
                return f"{domain}.edgekey.net"
            elif check_domain(f"{domain}.edgesuite.net"):
                return f"{domain}.edgesuite.net"
        else:
            if check_domain(f"{domain}.edgekey-staging.net"):
                return f"{domain}.edgekey-staging.net"
            elif check_domain(f"{domain}.edgesuite-staging.net"):
                return f"{domain}.edgesuite-staging.net"
        return False

    for cname in cnames:
        # Convert CNAME to string
        cname = str(cname)
        # Check if CNAME is an akamai domain name
        if "edgekey-staging.net" in cname or "edgekey.net" in cname or "edgesuite.net" in cname or "edgesuite-staging.net" in cname:
            # If prod check that the domain is edgekey or staging, if not return a prod name
            if prod:
                if "edgekey.net" in cname or "edgesuite.net" in cname:
                    if cname[-1] == ".":
                        cname = cname[:-1]
                    return cname
                else:
                    cname.replace("edgekey-staging.net", "edgekey.net")
                    cname.replace("edgesuite-staging.net", "edgesuite.net")
                    if cname[-1] == ".":
                        cname = cname[:-1]
                    return cname
            else:
                if "edgekey-staging.net" in cname or "edgesuite-staging.net" in cname:
                    if cname[-1] == ".":
                        cname = cname[:-1]
                    return cname
                else:
                    cname.replace("edgekey.net", "edgekey-staging.net")
                    cname.replace("edgesuite.net", "edgesuite-staging.net")
                    if cname[-1] == ".":
                        cname = cname[:-1]
                    return cname

def create_session(domain: str) -> requests.Session:
    session = requests.Session()
    session.mount('https://', FrontingAdapter(fronted_domain=domain))
    session.headers = {
        "Host": domain,
        "Pragma": "akamai-x-get-client-ip, akamai-x-cache-on, akamai-x-cache-remote-on, akamai-x-check-cacheable, akamai-x-get-cache-key, akamai-x-get-extracted-values, akamai-x-get-nonces, akamai-x-get-ssl-client-session-id, akamai-x-get-true-cache-key, akamai-x-serial-no, akamai-x-feo-trace, akamai-x-get-request-id, akamai-x-get-client-ip, akamai-x-ro-trace"
    }
    session.verify = False
    session.allow_redirects = False
    return session
   
def parse_request(headers, domain: str, akamai_cdn_route: str, domain_fronting: bool|None = None) -> str:
    """
    Returns a parsed string of headers
    """
    response_str = ""
    if not headers:
        return f"[{domain} via {akamai_cdn_route}] Domain does not exist, unable to perform request..\n"
    if domain_fronting:
        head = f"[{domain} via {akamai_cdn_route}]"
    else:
        head = f"[{domain} via {akamai_cdn_route} - via HTTP (NO FRONTING)]"
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
    return response_str
    
with open(args.filename_out, "w+") as output_file:
    with open(args.filename_in, "r") as akamai_domains:
        for akamai_domain in akamai_domains:
            akamai_domain = akamai_domain.lstrip().rstrip()
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
                output_file.write(parse_request(False, akamai_domain, akamai_cdn_name_prod)+"\n\n")
            else:
                try:
                    output_file.write(parse_request(session.get(f"https://{akamai_cdn_name_prod}").headers, akamai_domain, akamai_cdn_name_prod, True)+"\n\n")
                except:
                    print(f"TLS ERROR for {akamai_domain} via {akamai_cdn_name_prod}! Continuing...\n")
                try:
                    output_file.write(parse_request(requests.get(f"http://{akamai_cdn_name_prod}", headers=headers, allow_redirects=False).headers, akamai_domain, akamai_cdn_name_prod, False)+"\n\n")
                except:
                    # Other errors, like too many redirects...
                    print(f"ERROR! {akamai_domain} via {akamai_cdn_name_prod} failed! Skipping...\n")
                    output_file.write(f"ERROR! {akamai_domain} via {akamai_cdn_name_prod} failed! Skipping...\n\n")                       

            # Staging
            if not akamai_cdn_name_staging:
                output_file.write(parse_request(False, akamai_domain, akamai_cdn_name_staging)+"\n\n")
            else:
                try:
                    output_file.write(parse_request(session.get(f"https://{akamai_cdn_name_staging}").headers, akamai_domain, akamai_cdn_name_staging, True)+"\n\n")
                except:
                    print(f"TLS ERROR for {akamai_domain} via {akamai_cdn_name_staging}! Continuing...\n")
                try:
                    output_file.write(parse_request(requests.get(f"http://{akamai_cdn_name_staging}", headers=headers, allow_redirects=False).headers, akamai_domain, akamai_cdn_name_staging, False)+"\n\n")
                except:
                    # Other errors, like too many redirects...
                    print(f"ERROR! {akamai_domain} via {akamai_cdn_name_staging} failed! Skipping...\n")
                    output_file.write(f"ERROR! {akamai_domain} via {akamai_cdn_name_staging} failed! Skipping...\n\n")
