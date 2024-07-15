# acme-controller

This program automates certificate management processes using the ACME protocol with Cloudflare as the DNS provider. It supports multiple identifiers and allows specification of contact mail, challenge type, API token, and zone ID either through command line arguments or environment variables.


# Configuration
## Before running the application, configure the necessary environment variables. These variables include domain identifiers, contact emails, API tokens, and other required details for ACME certification:

``` 
DOMAIN_IDENTIFIERS: A comma-separated list of domain identifiers (e.g., example.com,.example.com).
CONTACT_MAILS: Contact email addresses for the ACME account (e.g., user@example.com).
API_TOKEN: API token for DNS provider (Cloudflare) integration.
ZONE_ID: Zone ID for the DNS provider (Cloudflare).
URL: ACME directory URL (Let's Encrypt's staging/production).
RENEWAL_THRESHOLD: Days before expiration to attempt renewal.
```