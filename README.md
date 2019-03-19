# godet
Gathers various details regarding an IP or domain, such as blacklists (blacklists/RBLs), and various HTTP & DNS operations. Posts the results at a configurable endpoint.  
Can be ran as a serverless app.

##### Current project state: BETA

### Setup
* `git clone https://github.com/foae/godet`
* check the `Makefile` and adjust the configuration to fit your needs
* the HTTP server will expose 3 HTTP GET endpoints:
  *  `/target/details` | usage: `/target/details?target=1.1.1.1`
  *  `/target/blacklists` | usage: `/target/details?target=1.1.1.1`
      * in return, the program will POST at the configured endpoints its findings.
      * `target` can be any IPv4 or domain (FQDN)
  *  `/health`
  * the HTTP server runs with a configurable `AccessKey` that _you_ need to set in your client's header when accessing the service's endpoints. **Default: `foobar`**
* optionally, in the `rbl` folder you can adjust the IP and domain blacklists to be checked against. _This will be eventually moved into a configurable file_.
* run the program `make run`

### Main functions:
1. Blacklist check (blocklist/RBL)  
* 97 IP RBLs
* 34 domain RBLs
2. IP or domain details scraper
* http_quick - HTTP response code check
* http_details - HTTP quick + headers
* https_quick - HTTPS response code check
* https_details - HTTPS quick + headers + TLS details
* ping - performs a simple PING
* dkim - DKIM record(s)
* spf - SPF record(s)
* dmarc - DMARC record(s)
* hostname 
* asn - IP ASN (in case of a domain, ASN of the IP the domain points to) 
* country - country of the IP (country of the IP that the domain points to, in case of a domain)
* mx - MX record(s)
* smtp25 - SMTP on port 25
* smtp465 - SMPT on port 465
* smtp587 - SMPT on port 587
* imap143 - IMAP on port 143
* imap993 - IMAP on port 993
* pop3110 - POP3 on port 110
* pop3s995 - POP3 on port 995

### Dependencies
* `dig` installed on the OS (uh, uh)
* `github.com/sparrc/go-ping`

### Under development
* removing `dig` dependency and start using a native implementation
* storing the details in a Redis instance
* configurable IP/domain blacklists to check against
* add `Output` and `Result` JSON examples
* cover with tests