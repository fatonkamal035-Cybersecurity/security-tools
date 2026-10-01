# security-tools

A collection of Python tools for cybersecurity learning, network inspection, OSINT, web security, and defensive research.

## Overview

`security-tools` is a modular collection of small Python utilities designed to make common security-related tasks easier to explore, test, and understand.

Each tool is maintained in its own directory, with source code, tests, and a dependency file when external packages are required.

The project focuses on practical implementations, input validation, predictable behavior, and testable code.

## Features

* Network information and TCP connectivity checks
* DNS record lookups and hostname resolution
* Domain registration and web resource inspection
* HTTP security header and TLS certificate inspection
* File hashing and hash verification
* Basic dependency inventory
* Unit tests for individual tools

## Tool Inventory

### Network

| Tool           | Description                                               |
| -------------- | --------------------------------------------------------- |
| `network-info` | Collects local network interface and address information. |
| `port-check`   | Checks TCP connectivity to a specified host and port.     |

### Web Security

| Tool               | Description                              |
| ------------------ | ---------------------------------------- |
| `security-headers` | Inspects HTTP security headers.          |
| `robots-info`      | Retrieves a website's `robots.txt` file. |
| `tls-info`         | Retrieves TLS certificate metadata.      |

### OSINT and DNS

| Tool              | Description                                              |
| ----------------- | -------------------------------------------------------- |
| `whois-info`      | Retrieves domain registration information through WHOIS. |
| `dns-info`        | Resolves hostnames to address information.               |
| `dns-records`     | Looks up DNS address records.                            |
| `subdomain-info`  | Resolves an explicitly supplied hostname.                |
| `http-status`     | Checks the HTTP status of a URL.                         |
| `dns-txt-info`    | Looks up DNS TXT records.                                |
| `dns-mx-info`     | Looks up DNS MX records.                                 |
| `dns-ns-info`     | Looks up DNS NS records.                                 |
| `dns-soa-info`    | Looks up DNS SOA records.                                |
| `dns-caa-info`    | Looks up DNS CAA records.                                |
| `dns-ds-info`     | Looks up DNSSEC DS records.                              |
| `dns-dnskey-info` | Looks up DNSSEC DNSKEY records.                          |
| `dns-srv-info`    | Looks up DNS SRV records.                                |
| `dns-naptr-info`  | Looks up DNS NAPTR records.                              |
| `dns-cname-info`  | Looks up DNS CNAME records.                              |
| `dns-ptr-info`    | Looks up DNS PTR records.                                |
| `dns-sshfp-info`  | Looks up DNS SSHFP records.                              |
| `dns-hinfo-info`  | Looks up DNS HINFO records.                              |
| `dns-rp-info`     | Looks up DNS RP records.                                 |
| `dns-svcb-info`   | Looks up DNS SVCB records.                               |
| `dns-https-info`  | Looks up DNS HTTPS records.                              |
| `dns-uri-info`    | Looks up DNS URI records.                                |
| `dns-tlsa-info`   | Looks up DNS TLSA records used with DANE.                |

### Cryptography

| Tool          | Description                                      |
| ------------- | ------------------------------------------------ |
| `hash-verify` | Compares a supplied hash with an expected value. |

### Defensive Security

| Tool                 | Description                                                |
| -------------------- | ---------------------------------------------------------- |
| `file-hash`          | Calculates file hashes for integrity verification.         |
| `dependency-auditor` | Parses pinned dependencies from a `requirements.txt` file. |

## Requirements

* Python 3.9 or newer
* Git
* Internet access for tools that query external DNS or network services
* `pip` for installing Python dependencies

Some tools use Python's standard library and do not require additional packages. Others have their own `requirements.txt` file.

## Installation

### 1. Clone the Repository

```bash
git clone https://github.com/fatonkamal035-Cybersecurity/security-tools.git
cd security-tools
```

### 2. Create a Virtual Environment

Using a virtual environment helps keep project dependencies separate from system Python packages.

**Linux / Kali Linux / macOS**

```bash
python3 -m venv .venv
source .venv/bin/activate
```

**Windows PowerShell**

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
```

If the `venv` module is unavailable, install or enable the appropriate Python environment support for your operating system.

### 3. Install Dependencies for a Tool

Dependencies are managed per tool. Install only the packages required by the tool you intend to use.

For example, to prepare `dns-tlsa-info`:

```bash
python -m pip install -r tools/osint/dns-tlsa-info/requirements.txt
```

The same pattern applies to other tools that contain a `requirements.txt` file. Replace the path with the relevant tool directory.

For a tool without a requirements file, check its source code for external dependencies.

### 4. Verify the Installation

Run the repository's test suite:

```bash
python -m pip install pytest
pytest -q
```

A passing test suite verifies the behavior covered by those tests. It does not guarantee that every tool works in every network environment or against every target.

## Usage

The tools are currently organized as Python modules. The repository does not yet provide a unified command-line interface or a single package installation command.

Read the relevant source file before using a tool to understand its function, accepted inputs, and return values.

### Example: DNS TLSA Lookup

Install the tool's dependency first:

```bash
python -m pip install -r tools/osint/dns-tlsa-info/requirements.txt
```

On Linux or Kali Linux, query a TLSA owner name with:

```bash
PYTHONPATH=tools/osint/dns-tlsa-info/src python -c "from dns_tlsa_info import resolve_tlsa_records; print(resolve_tlsa_records('_443._tcp.example.com'))"
```

Replace `_443._tcp.example.com` with the TLSA owner name you are authorized to query.

The function returns a list of records containing the usage, selector, matching type, and certificate association data. An empty list means no records were returned successfully by the function; it does not establish why the lookup returned no records.

### Run Tests for One Tool

For example, test `dns-tlsa-info`:

```bash
PYTHONPATH=tools/osint/dns-tlsa-info/src pytest -q tools/osint/dns-tlsa-info/tests
```

For another tool, replace the source and test paths with its own directory.

## Repository Structure

```text
security-tools/
└── tools/
    ├── crypto/
    │   └── hash-verify/
    ├── defensive/
    │   └── file-hash/
    ├── network/
    │   ├── network-info/
    │   └── port-check/
    ├── osint/
    │   ├── dns-info/
    │   ├── dns-records/
    │   ├── dns-tlsa-info/
    │   └── ...
    ├── vulnerability/
    │   └── dependency-auditor/
    └── web/
        ├── security-headers/
        ├── robots-info/
        └── tls-info/
```

Each tool directory contains its implementation and, where provided, a dedicated test suite and dependency file.

## Security and Limitations

* Use these tools only against systems, domains, and services you own or are explicitly authorized to assess.
* DNS results depend on resolver configuration, DNS propagation, and the target's records.
* A failed connection, missing record, or empty result does not automatically indicate a vulnerability.
* `dependency-auditor` inventories pinned dependencies; it is not a CVE database or a full vulnerability scanner.
* TLS certificate metadata alone does not constitute a complete TLS security assessment.
* HTTP security header inspection does not replace a broader application security assessment.
* Network responses and external services can change over time.
* Review the source code before using a tool in a production environment.

## Development and Testing

Contributions should keep tools modular and include tests for new behavior and input validation.

Before submitting a change:

1. Review the implementation and its dependencies.
2. Run the relevant tool-specific tests.
3. Run the full test suite.
4. Check the Git diff for unintended changes.
5. Document important limitations and usage requirements.

Avoid hardcoded credentials, unnecessary dependencies, and unsupported security claims.

## Contributing

Issues, bug reports, and improvements are welcome.

When reporting a problem, include the affected tool, the steps needed to reproduce it, the expected behavior, and the actual result. Do not include passwords, tokens, private keys, or other sensitive information.

## License

No license has been specified for this repository yet. Unless a license is added, do not assume that the code is available for unrestricted reuse, modification, or redistribution.
