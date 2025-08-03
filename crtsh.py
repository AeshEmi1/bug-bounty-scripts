#!/usr/bin/env python3
import sys, argparse, requests, json

subdomains = set()
wildcardsubdomains = set()


def parser_error(errmsg):
    print("Usage: python3 " + sys.argv[0] + " [Options] use -h for help")
    print("Error: " + errmsg)
    sys.exit()


def parse_args():
    parser = argparse.ArgumentParser(
        epilog="\tExample: \r\npython3 " + sys.argv[0] + " -d google.com"
    )
    parser.error = parser_error
    parser._optionals.title = "OPTIONS"
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
    parser.add_argument(
        "-s", "--stdout", help="Print output", action="store_true", required=False
    )
    return parser.parse_args()


def crtsh(domain: str):
    """
    Returns a set of domains.
    """
    try:
        response = requests.get(
            f"https://crt.sh/?q={domain.lstrip().rstrip()}&output=json", timeout=25
        )
        if response.ok:
            content = response.content.decode("UTF-8")
            jsondata = json.loads(content)
            for i in range(len(jsondata)):
                name_value = jsondata[i]["name_value"]
                if name_value.find("\n"):
                    subname_value = name_value.split("\n")
                    for subname_value in subname_value:
                        if subname_value.find("*"):
                            subdomains.add(subname_value)
                        else:
                            wildcardsubdomains.add(subname_value)
        else:
            print(f"ERROR! RESPONSE: {response.json()}")
    except:
        print("ERROR! Timeout Exceeded.")
        pass


if __name__ == "__main__":
    args = parse_args()
    if args.output_file:
        output_file = open(args.output_file, "w+")
    if args.domain:
        crtsh(args.domain)
        # Check that there are actually subdomains to iterate through
        if subdomains:
            for subdomain in subdomains:
                if args.output_file:
                    output_file.write(f"{subdomain}\n")
                print(subdomain)
    elif args.domain_file:
        with open(args.domain_file, "r") as domain_file:
            for domain in domain_file:
                crtsh_output = crtsh(domain)
        # Check that there are actually subdomains to iterate through
        if subdomains:
            for subdomain in subdomains:
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
