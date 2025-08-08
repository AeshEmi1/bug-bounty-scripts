# Bug Bounty Scripts

This repo contains scripts I use for bug bounties. My tools currently focus on subdomain enumeration and origin discovery.

## Main Scripts

- `crtsh.py`: A forked script that uses crt.sh to enumerate subdomains for a given target domain.

- `find_origins.py`: A script that attempts to find origin hostnames using Akamai pragma headers, crt.sh, and subdomain enumeration.

## Prerequisites and Installation

These scripts require Python 3 to run (my bad for not including a requirements.txt file).

## Usage

### find_origins.py
``` bash
find_origins.py domains.txt --ch pragma_header_output.txt --origin_outfile potential_origins.txt
```

### crtsh.py

Get subdomains for a single domain:
``` bash
crtsh.py -d example.com -o example_subdomains.txt
```

Get subdomains for a list of domains:
``` bash
crtsh.py -f domains_file.txt -o example_subdomains.txt
```