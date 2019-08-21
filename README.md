# Polarity urlscan Integration
The Polarity urlscan integration will lookup domains and ips in urlscan and notify you about information such as date last scanned, and relevant in relation to the ip and domain.

To learn more about urlscan, please visit: https://urlscan.io/about/

Check out the integration below:



## urlscan Integration Options

### urlscan URL
The base URL to use for the urlscan API. Default is set to: https://urlscan.io/api

### urlscan Results
The maximum number of results to return to the Polarity overlay window.

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
