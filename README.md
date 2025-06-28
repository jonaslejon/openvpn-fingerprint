# OpenVPN Fingerprinting Tool

```
                                    __ _                            _     _
 ___ _ __  ___ _ ___ ___ __ _ _    / _(_)_ _  __ _ ___ _ _ _ __ _ _(_)_ _| |_
/ _ \ '_ \/ -_) ' \ V / '_ \ ' \  |  _| | ' \/ _` / -_) '_| '_ \ '_| | ' \  _|
\___/ .__/\___|_||_\_/| .__/_||_| |_| |_|_||_\__, \___|_| | .__/_| |_|_||_\__|
    |_|               |_|                    |___/        |_|
                                                                
🔍 OpenVPN Fingerprinting Tool v2.4.2 🔍
```

![Python](https://img.shields.io/badge/python-3.7+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Status](https://img.shields.io/badge/status-active-success.svg)

This repository contains an enhanced implementation of the OpenVPN TCP/UDP Fingerprinting Tool, based on the research paper ["OpenVPN Is Open to VPN Fingerprinting"](https://cacm.acm.org/research/openvpn-is-open-to-vpn-fingerprinting/) (ACM CACM 2024).

The tool analyzes the responses of a server to a series of specially crafted probes to determine if it is running OpenVPN. It includes advanced techniques for higher accuracy and more detailed analysis.

## Features

This enhanced version includes several improvements over the base model described in the paper:

-   **Adaptive Confidence Thresholds**: Dynamically adjusts detection sensitivity.
-   **Improved RST Pattern Detection**: More accurately interprets TCP RST packets.
-   **Connection Timeout Analysis**: Uses timeout patterns as an indicator.
-   **Retry Logic**: Handles transient network failures for more reliable scanning.
-   **Enhanced UDP Response Analysis**: Deeper analysis of UDP packet responses.
-   **Probe Order Randomization**: Avoids simple signature-based detection of the scanner.
-   **Adaptive Timeout Calculation**: Adjusts timeouts based on network conditions.
-   **Statistical Confidence Calculation**: Uses a Bayesian model for confidence scores.
-   **Evidence Weighting System**: Prioritizes more reliable indicators of OpenVPN.
-   **Server Behavioral Profiling**: Matches server behavior against known OpenVPN configuration profiles.

## Usage

You can run the tool directly with Python or use the provided Docker image.

### Requirements

Install the required Python libraries:

```bash
pip install -r requirements.txt
```

### Direct Execution

The main script is `openvpn-fingerprint.py`.

```bash
# Scan a single target on both TCP and UDP
python3 openvpn-fingerprint.py -t 1.2.3.4

# Scan a single target on a specific port and protocol
python3 openvpn-fingerprint.py -t 1.2.3.4 -p 443 --protocol tcp

# Scan a list of targets from a file with verbose output
python3 openvpn-fingerprint.py -f targets.txt -v --protocol udp

# Enable super-verbose output for deep analysis
python3 openvpn-fingerprint.py -t example.com --protocol both -vv

# Output results to a JSON file
python3 openvpn-fingerprint.py -f targets.txt --json > results.json
```

### Docker Usage

The tool is available as a Docker image: `jonaslejon/openvpn-fingerprint`.

```bash
# Scan a single target
docker run --rm jonaslejon/openvpn-fingerprint -t 1.2.3.4
```

## Efficiency Testing

This repository also includes `efficieny-test.py`, a script for testing the accuracy and performance of the fingerprinting tool using data from Shodan.

The script processes a Shodan JSON data file, runs the fingerprinting tool against the identified OpenVPN targets, and generates a detailed analysis report with performance metrics and visualizations.

### Test Script Usage

First download some data from Shodan using the Shodan CLI:
```bash
shodan download openvpn.csv port:1194
```
Then run the tests:
```bash
# Run a test with a Shodan JSON file and save results to the 'results/' directory
python3 efficieny-test.py -f openvpn.json.gz -o results/

# Run a test on a sample of 1000 hosts with verbose output
python3 efficieny-test.py --shodan-file openvpn.json.gz --sample 1000 --verbose

# Run a test with custom fingerprinting parameters
python3 efficieny-test.py -f openvpn.json.gz --threads 100 --timeout 10 -v
```

## Disclaimer

This tool is intended for educational and research purposes only. Unauthorized scanning of networks is illegal. The user is responsible for their own actions.
