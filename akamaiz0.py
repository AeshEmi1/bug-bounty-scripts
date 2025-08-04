#!/usr/bin/python3
from logging_settings import configure_logging
from modules.HelperMethods import HTTPHelpers, DNSHelpers
import tldextract
import structlog
import argparse
import http.client
import re

# To avoid running into 100 header limit
http.client._MAXHEADERS = 1000
logger = structlog.get_logger(__name__)


class AkamaiZ0:
    """Contains methods that attack insecure Akamai implementations"""

    AKAMAI_STRINGS = {
        "edgekey-staging.net",
        "edgekey.net",
        "edgesuite.net",
        "edgesuite-staging.net",
        "akamaized.net",
        "akamaiedge.net",
    }

    @staticmethod
    def is_akamai_domain(domain: str) -> bool:
        """Checks if a domain is pointing to Akamai

        Args:
            domain (str): The domain you want to check.

        Returns:
            bool: True if the domain is pointing to Akamai, False if not.
        """

        cname = DNSHelpers.get_cname(domain)

        if any(akamai_string in cname for akamai_string in AkamaiZ0.AKAMAI_STRINGS):
            return True

        return False

    @staticmethod
    def get_custom_headers(
        original_domain: str,
        domain: str = None,
        custom_headers: dict[str, str | dict | int] = None,
    ) -> dict | None:
        """Tries to get custom headers (including Akamai pragma headers) from a domain

        Args:
            domain (str): The domain you want to retrieve custom headers from

        Returns:
            dict[str, str]: The returned domain route and custom headers, or None if none were returned.
                {"route": "lululemon.fr.edgekey.net", "custom_header_dict": {"header1": "stuff"}, "status_code": 200}
        """
        request_headers = {
            "Host": original_domain,
            "Pragma": "akamai-x-get-client-ip, akamai-x-cache-on, akamai-x-cache-remote-on, akamai-x-check-cacheable, akamai-x-get-cache-key, akamai-x-get-extracted-values, akamai-x-get-nonces, akamai-x-get-ssl-client-session-id, akamai-x-get-true-cache-key, akamai-x-serial-no, akamai-x-feo-trace, akamai-x-get-request-id, akamai-x-get-client-ip, akamai-x-ro-trace",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:126.0) Gecko/20100101 Firefox/126.1",
        }

        if not domain:
            domain = original_domain
        if not custom_headers:
            custom_headers: dict[str, str] = {}
            custom_headers["route"]: str = ""
            custom_headers["custom_header_dict"]: dict[str, str] = {}

        # Checks that the domain is valid before updaing the custom_headers dict
        if DNSHelpers.check_domain(domain):
            get_request = HTTPHelpers.get_request(
                f"http://{domain}/favicon.ico", request_headers
            )

            # Try HTTPS instead if the request fails
            if get_request is False:
                get_request = HTTPHelpers.get_request(
                    f"https://{domain}/favicon.ico", request_headers
                )

            if get_request is not None:
                custom_headers["status_code"] = get_request.status_code
                custom_headers["custom_header_dict"].update(
                    {
                        header_name: header_value
                        for (header_name, header_value) in get_request.headers.items()
                        if header_name.startswith("X-")
                        or header_name.lower() == "server"
                    }
                )
                cname = DNSHelpers.get_cname(domain)
                if cname:
                    custom_headers["route"] = cname
                else:
                    custom_headers["route"] = DNSHelpers.get_A(domain)

        # Check for Akamai pragma headers
        if "X-Cache-Key" not in custom_headers["custom_header_dict"]:
            # Check that the domain isn't already an Akamai domain (if it is, it has been recursively run already)
            if any(
                akamai_string in domain for akamai_string in AkamaiZ0.AKAMAI_STRINGS
            ):
                # If this is an Akamai domain and there's no cache key value, pragma headers are disabled. return what we have already
                if DNSHelpers.get_A(domain):
                    return custom_headers
                elif "edgekey.net" in domain:
                    return AkamaiZ0.get_custom_headers(
                        original_domain,
                        f"{tldextract.extract(domain).subdomain}.edgekey-staging.net",
                        custom_headers,
                    )
                elif "edgekey-staging.net" in domain:
                    return AkamaiZ0.get_custom_headers(
                        original_domain,
                        f"{tldextract.extract(domain).subdomain}.edgesuite.net",
                        custom_headers,
                    )
                elif "edgesuite.net" in domain:
                    return AkamaiZ0.get_custom_headers(
                        original_domain,
                        f"{tldextract.extract(domain).subdomain}.edgesuite-staging.net",
                        custom_headers,
                    )
                elif "edgesuite-staging.net" in domain:
                    return AkamaiZ0.get_custom_headers(
                        original_domain,
                        f"{tldextract.extract(domain).subdomain}.akamaized.net",
                        custom_headers,
                    )
                # This is reached whenever the domain is invalid and we've exhausted all edge hostnames (likely the domain is not behind akamai)
                else:
                    return custom_headers
            # If the CNAME is not an Akamai domain, try a normal edgekey domain.
            elif not AkamaiZ0.is_akamai_domain(domain):
                extracted_domain = tldextract.extract(domain)
                if extracted_domain.subdomain:
                    return AkamaiZ0.get_custom_headers(
                        original_domain,
                        f"{extracted_domain.subdomain}.{extracted_domain.domain}.edgekey.net",
                        custom_headers,
                    )
                else:
                    return AkamaiZ0.get_custom_headers(
                        original_domain,
                        f"{extracted_domain.domain}.edgekey.net",
                        custom_headers,
                    )
            # If the CNAME is an Akamai domain, return the current headers (pragma headers are disabled)
            return custom_headers
        return custom_headers


class ContentParsers:
    """Contains methods to parse various outputs"""

    @staticmethod
    def parse_custom_headers(
        domain_and_header_dict: dict[str, dict], file_name: str
    ) -> None:
        """Parses AkamaiZ0.AkamaiZ0.get_custom_headers() and writes it to a file.

        Args:
            domain_and_header_dict (dict): Contains the domain and route
                {"lululemon.fr": {"route": "lululemon.fr.edgekey.net", "custom_header_dict": {"header1": "stuff"}, "status_code": 200}}
        """

        with open(file_name, "w") as custom_header_file:
            for domain in domain_and_header_dict:
                if domain_and_header_dict[domain]["custom_header_dict"]:
                    route = domain_and_header_dict[domain]["route"]
                    status_code = domain_and_header_dict[domain]["status_code"]
                    for header_name, header_value in domain_and_header_dict[domain][
                        "custom_header_dict"
                    ].items():
                        custom_header_file.write(
                            f"[{domain} via {route} ({status_code})] {header_name}: {header_value}\n"
                        )
                elif "status_code" not in domain_and_header_dict[domain]:
                    custom_header_file.write(f"[{domain}] - Returned an error!\n")
                elif domain_and_header_dict[domain]["status_code"] == 403:
                    custom_header_file.write(
                        f"[{domain} via {route} ({status_code})] - No custom headers, but {status_code} returned...\n"
                    )

    @staticmethod
    def get_potential_origins(domain_and_header_dict: dict[str, list]) -> dict:
        """Tries to get custom origins and writes them to a dict.

        Args:
            domain_and_header_dict (dict): Contains the domain, route and status_code
                {"lululemon.fr": {"route": "lululemon.fr.edgekey.net", "custom_header_dict": {"header1": "stuff"}, "status_code": 200}}

        Returns:
            dict: Potential origins
                {"potential_origin.example.com": ["main_domain.example.com", "example.com"]}
        """

        origin_dict: dict[str, list] = {}
        for domain in domain_and_header_dict:
            if "X-Cache-Key" in domain_and_header_dict[domain]["custom_header_dict"]:
                potential_origin = domain_and_header_dict[domain]["custom_header_dict"][
                    "X-Cache-Key"
                ].split("/")[5]
                if DNSHelpers.get_A(potential_origin):
                    potential_origin = (
                        f"{potential_origin} ({DNSHelpers.get_A(potential_origin)})"
                    )
                if potential_origin not in origin_dict:
                    origin_dict[potential_origin] = []
                attributes = []
                try:
                    property_name: str = re.search(
                        r"name=AKA_PM_PROPERTY_NAME;\s*value=([^,;]*)",
                        domain_and_header_dict[domain]["custom_header_dict"][
                            "X-Akamai-Session-Info"
                        ],
                    )
                    attributes.append(f"AKA_PM_PROPERTY_NAME={property_name.group(1)}")
                except:
                    pass
                try:
                    property_version: str = re.search(
                        r"name=AKA_PM_PROPERTY_VERSION;\s*value=([^,;]*)",
                        domain_and_header_dict[domain]["custom_header_dict"][
                            "X-Akamai-Session-Info"
                        ],
                    )
                    attributes.append(
                        f"AKA_PM_PROPERTY_VERSION={property_version.group(1)}"
                    )
                except:
                    pass
                try:
                    custom_variables: dict[str, str] = re.findall(
                        r"(name=PMUSER[^;,\s]*); value=([^,;]*)",
                        domain_and_header_dict[domain]["custom_header_dict"][
                            "X-Akamai-Session-Info"
                        ],
                    )
                    for key, value in custom_variables:
                        # Remove the name= prefix from the key
                        cleaned_key = key.replace("name=", "")
                        attributes.append(f"{cleaned_key}={value}")
                except:
                    pass
                try:
                    datastream_status: str = re.search(
                        r"name=DATASTREAM_LOGGING_EXECUTED;\s*value=([^,;]*)",
                        domain_and_header_dict[domain]["custom_header_dict"][
                            "X-Akamai-Session-Info"
                        ],
                    )
                    attributes.append(
                        f"DATASTREAM_LOGGING_EXECUTED={datastream_status.group(1)}"
                    )
                except:
                    pass
                origin_dict[potential_origin].append(
                    f"{domain} {[attribute for attribute in attributes]}"
                )

        return origin_dict


def get_custom_headers_from_file(
    domain_file: str, header_output_file: str, origin_outfile: str
) -> None:
    """Retrieves custom headers

    Args:
        domain_file (str): The file with domains to be scanned.
    """

    domain_and_header_dict = {}
    with open(domain_file, "r") as domains:
        for domain in domains:
            domain = domain.strip()
            logger.info("Getting custom headers...", domain=domain)
            domain_and_header_dict[domain] = AkamaiZ0.get_custom_headers(domain)

    ContentParsers.parse_custom_headers(domain_and_header_dict, header_output_file)
    logger.info("File written successfully!", file=custom_headers_file)

    origin_dict = ContentParsers.get_potential_origins(domain_and_header_dict)
    if origin_dict:
        with open(origin_outfile, "w") as potential_origin_file:
            other_domains = []
            for potential_origin in origin_dict:
                # Checks that the origin and the visible domain are not the same when the number of visible names to potential origins is 1.
                if not (
                    len(origin_dict[potential_origin]) == 1
                    and potential_origin.split(" ")[0]
                    == origin_dict[potential_origin][0].split(" ")[0]
                ):
                    potential_origin_file.write(
                        f"Potential origin: {potential_origin}\n"
                    )
                    for main_domain in origin_dict[potential_origin]:
                        potential_origin_file.write(f"- {main_domain}\n")
                    potential_origin_file.write("\n")
                else:
                    # For domains that's Cache key is the same as the incoming host header instead of the origin server add it to a list for those to be parsed separately.
                    other_domains.extend(origin_dict[potential_origin])

            if other_domains:
                potential_origin_file.write("Other domains:\n")
                for other_domain in other_domains:
                    potential_origin_file.write(f"- {other_domain}\n")
        logger.info("File written successfully!", file=origin_outfile)
    else:
        logger.info("No potential origins :(")


if __name__ == "__main__":
    try:
        configure_logging(log_file_path="akamaiz0.log")

        parser = argparse.ArgumentParser(
            prog="akamaiz0.py",
            description="Exploits for insecure Akamai implementations",
        )
        parser.add_argument(
            "domains_file", help="Specify filename with domains to be scanned."
        )
        parser.add_argument(
            "--ch",
            help="Specify output filename for the custom headers file, optional.",
        )
        parser.add_argument(
            "--origin_outfile",
            help="Specify output filename for the potential origins, optional.",
        )
        args = parser.parse_args()

        if args.ch:
            custom_headers_file = args.ch
        else:
            custom_headers_file = "custom_headers.txt"

        if args.origin_outfile:
            potential_origin_file = args.origin_outfile
        else:
            potential_origin_file = "potential_origins.txt"

        get_custom_headers_from_file(
            args.domains_file, custom_headers_file, potential_origin_file
        )
    except:
        logger.critical("A critical error has occured", exc_info=True)
