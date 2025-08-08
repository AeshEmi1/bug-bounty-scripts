"""
Gets certificate info for a domain and it's subdomains.
"""

#!/usr/bin/env python3
import sys
import argparse
import json
import structlog
import requests
from logging_settings import configure_logging

logger = structlog.get_logger(__name__)


def parser_error(errmsg):
    print("Usage: python3 " + sys.argv[0] + " [Options] use -h for help")
    print("Error: " + errmsg)
    sys.exit()


def parse_args():
    parser = argparse.ArgumentParser(
        epilog="\tExample: \r\npython3 " + sys.argv[0] + " -d google.com"
    )
    parser.error = parser_error
    parser.add_argument(
        "-d",
        "--domain",
        help="Specify Target Domain to get subdomains from crt.sh",
        required=False,
    )
    parser.add_argument(
        "-f",
        "--domain_file",
        help="Specify a Target Domain File to get subdomains from crt.sh",
        required=False,
    )
    parser.add_argument(
        "-o", "--output_file", help="Specify an output file", required=False
    )
    parser.add_argument(
        "-r",
        "--recursive",
        help="Do recursive search for subdomains",
        action="store_true",
        required=False,
    )
    parser.add_argument(
        "-w",
        "--wildcard",
        help="Include wildcard in output",
        action="store_true",
        required=False,
    )
    return parser.parse_args()


def crtsh(root_domain: str) -> dict(str, set):
    """Retrieves domains from the crt.sh output

    Args:
        root_domain (str): The root domain to get all certificates for

    Returns:
        dict(str, set): A dict of found subdomains from certificate info
    """
    subdomains = set()
    wildcardsubdomains = set()

    try:
        response = requests.get(
            f"https://crt.sh/?q={root_domain.lstrip().rstrip()}&output=json", timeout=25
        )
        if response.ok:
            content = response.content.decode("UTF-8")
            subdomain_data = json.loads(content)
            for subdomain in subdomain_data:
                name_value = subdomain["name_value"]
                if name_value.find("\n"):
                    subname_value = name_value.split("\n")
                    for subdomain in subname_value:
                        if "*" in subdomain:
                            wildcardsubdomains.add(subdomain)
                        else:
                            subdomains.add(subdomain)
        else:
            logger.error(f"RESPONSE: {response.json()}")
    except Exception:
        logger.error("ERROR! Timeout Exceeded.")
    return {"subdomains": subdomains, "wildcards": wildcardsubdomains}


if __name__ == "__main__":
    configure_logging(log_file_path="crtsh.log")
    args = parse_args()
    if args.output_file:
        output_file = open(args.output_file, "w+", encoding="utf-8")
    if args.domain:
        crtsh_dict = crtsh(args.domain)
        # Check that there are actually subdomains to iterate through
        if crtsh_dict["subdomains"]:
            for subdomain in crtsh_dict["subdomains"]:
                if args.output_file:
                    output_file.write(f"{subdomain}\n")
                print(subdomain)
    elif args.domain_file:
        all_subdomains: set = set()
        with open(args.domain_file, "r", encoding="utf-8") as domain_file:
            for domain in domain_file:
                all_subdomains.add(crtsh(domain)["subdomains"])
        # Check that there are actually subdomains to iterate through
        if all_subdomains:
            for subdomain in all_subdomains:
                if args.output_file:
                    output_file.write(f"{subdomain}\n")
                print(subdomain)

    # if args.recursive:
    #     for wildcardsubdomain in wildcardsubdomains.copy():
    #         wildcardsubdomain = wildcardsubdomain.replace('*.', '%25.')
    #         crtsh(wildcardsubdomain)

    # if args.wildcard:
    #     for wildcardsubdomain in wildcardsubdomains:
    #         print(wildcardsubdomain)
    output_file.close()
