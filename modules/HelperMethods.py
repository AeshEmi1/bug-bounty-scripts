import structlog
import requests
from socket import error as sock_err
import socket
import subprocess
logger = structlog.get_logger(__name__)


class HTTPHelpers:
    """Contains helper methods for making HTTP requests"""

    @staticmethod
    def get_request(url: str, headers: dict = None) -> requests.Response:
        """Sends a GET request

        Args:
            url (str): URL the request will be sent to.
            headers (dict, optional):HTTP Headers to be added to the request. Defaults to None

        Returns:
            requests.Response: Returns the GET request response from the server
        """
        try:
            request = requests.get(url, headers=headers, allow_redirects=False)
            logger.info("Request made", url=url, status_code=request.status_code)
            return request
        except:
            logger.error("Request failed", url=url, exc_info=True)
            return False


class DNSHelpers:
    """Contains helper methods for making DNS requests and checking connections"""

    @staticmethod
    def check_domain(hostname: str) -> bool:
        """Checks if a domain is up"""

        try:
            socket.setdefaulttimeout(2)
            socket.gethostbyname(hostname)
            return True
        except sock_err:
            return False

    @staticmethod
    def get_cname(domain: str) -> str | None | bool:
        """Returns the CNAME for a domain.

        Args:
            domain (str): Domain to perform DNS CNAME resolution against.

        Returns:
            str | bool: The CNAME record, or False if there was a failure.
        """

        try:
            cname: str = (
                subprocess.check_output(
                    ["dig", "+time=1", "+tries=2", domain, "CNAME", "+noall", "+short"]
                )
                .decode("utf-8")
                .lstrip()
                .rstrip()
                .lower()
            )
            return cname
        except:
            logger.error(f"DIG failed", domain=domain, exc_info=True)
            return False

    def get_A(domain: str) -> str | None | bool:
        """Returns the A records for a domain.

        Args:
            domain (str): Domain to perform DNS A resolution against.

        Returns:
            str | bool: The A record, or False if there was a failure.
        """

        try:
            cname: str = (
                subprocess.check_output(
                    ["dig", "+time=1", "+tries=2", domain, "+noall", "+short"]
                )
                .decode("utf-8")
                .strip()
                .lower()
            )
            return cname
        except:
            logger.error(f"DIG failed", domain=domain, exc_info=True)
            return False
