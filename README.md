# Polarity urlscan Integration
The Polarity urlscan integration will lookup domains, sha256 hashes, IPv4 and IPv6 addresses and IPv4 CIDRs in urlscan and provide contextual information about the entity.

To learn more about urlscan, please visit: https://urlscan.io/about/


| ![image](images/overlay.png) |
|---|
|*urlscan.io example* |

## Integration Overview

The `urlscan` integration will return results from the most recent relevant scan performed by the `urlscan` service.  After searching for the scan, additional scan details are returned by retrieving the overall verdict information to include whether the indicator is malicious, the overall score, tags, categories and brands.

## urlscan Integration Options

### urlscan URL
The base URL to use for the urlscan API. Default is set to: https://urlscan.io/api

### View Malicious Indicators Only

If checked, only indicators flagged as malicious will be returned

### Domain and IP Blacklist

This is an alternate option that can be used to specify domains or IPs that you do not want sent to UrlScan.  The data must specify the entire IP or domain to be blocked (e.g., www.google.com is treated differently than google.com).

### Domain Blacklist Regex

This option allows you to specify a regex to blacklist domains.  Any domain matching the regex will not be looked up.  If the regex is left blank then no domains will be blacklisted.

### IP Blacklist Regex

This option allows you to specify a regex to blacklist IPv4 Addresses.  Any IPv4 matching the regex will not be looked up.  If the regex is left blank then no IPv4s will be blacklisted.

## Installation Instructions

Installation instructions for integrations are provided on the [PolarityIO GitHub Page](https://polarityio.github.io/).

## Polarity

Polarity is a memory-augmentation platform that improves and accelerates analyst decision making.  For more information about the Polarity platform please see:

https://polarity.io/
