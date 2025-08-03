#!/usr/bin/python3
from logging_settings import configure_logging
from modules.HelperMethods import HTTPHelpers, DNSHelpers
import tldextract
import structlog
import argparse
import http.client

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
        original_domain: str, domain: str = None, custom_headers: dict[str, dict] = None
    ) -> dict | None:
        """Tries to get custom headers (including Akamai pragma headers) from a domain

        Args:
            domain (str): The domain you want to retrieve custom headers from

        Returns:
            dict[str, str]: The returned domain route and custom headers, or None if none were returned.
                {"route": "lululemon.fr.edgekey.net", "custom_header_dict": {"header1": "stuff"}}
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
            if get_request:
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
                {"lululemon.fr": {"route": "lululemon.fr.edgekey.net", "custom_header_dict": {"header1": "stuff"}}}
        """

        with open(file_name, "w") as custom_header_file:
            for domain in domain_and_header_dict:
                if domain_and_header_dict[domain]["custom_header_dict"]:
                    route = domain_and_header_dict[domain]["route"]
                    for header_name, header_value in domain_and_header_dict[domain][
                        "custom_header_dict"
                    ].items():
                        custom_header_file.write(
                            f"[{domain} via {route}] {header_name}: {header_value}\n"
                        )


def get_custom_headers_from_file(domain_file: str, output_file: str) -> None:
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

    ContentParsers.parse_custom_headers(domain_and_header_dict, output_file)


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
        args = parser.parse_args()

        if args.ch:
            custom_headers_file = args.ch
        else:
            custom_headers_file = "custom_headers.txt"

        get_custom_headers_from_file(args.domains_file, custom_headers_file)
        logger.info("File written successfully!", file=custom_headers_file)
    except:
        logger.critical("A critical error has occured", exc_info=True)
