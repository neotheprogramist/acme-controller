# acme-controller

This program automates certificate management processes using the ACME protocol with Cloudflare as the DNS provider. It supports multiple identifiers and allows specification of contact mail, challenge type, API token, and zone ID either through command line arguments or environment variables.


## example of usage with parameters
```sh 
cargo run -- -i "example.com,www.example.com" -m "your-email@example.com" -c "dns-01" -t "your_cloudflare_api_token" -z "your_cloudflare_zone_id > certificate"
```
## example of using env
```env

[env]
IDENTIFIERS = "your-domain.com,*.your-domain.com"
CONTACT_MAIL = "your-email.com"
CHALLANGE_TYPE = "dns-01"
API_TOKEN = "your_cloudflare_api_token"
ZONE_ID = "your_cloudflare_zone_id"
RUST_LOG="lib_acme=trace,acme_controller=trace"
```
```
cargo run 
```
