# acme-tiny-auto
Bash wrapper for acme_tiny.py. It helps you procure Let's Encrypt or Buypass certificates (single domain only, HTTP-01 validation only) in a few commands, renew them automatically, and it should not break your server if anything fails during renewal.

```
Usage: ./acme-tiny-auto.sh [init | add [domain]| renew [domain] | force-renew [domain] | renew-all ]
```

# Step by step instructions (Nginx)

## Create the folder for the scripts and certificates

All the steps below are to be run as `root`. We decided to store everything in a new path `/acme` ; update the commands and configurations accordingly if you choose another location.

```
mkdir -p /acme
```

## Send requests for /.well-known/acme-challenge to our custom folder

Make sure to create the webroot folder in advance (otherwise Nginx will fail to restart)

```
mkdir -p /acme/shared/.well-known/acme-challenge
```

Edit Nginx **default** server configuration for port 80 (you should see something like `listen 80 default_server;`) to add these 2 locations:
```   
    # From https://community.letsencrypt.org/t/how-to-nginx-configuration-to-enable-acme-challenge-support-on-all-http-virtual-hosts/5622 
    location ^~ /.well-known/acme-challenge/ {
        default_type "text/plain";
        root /acme/shared;
    }
    location = /.well-known/acme-challenge/ {
        return 404;
    }

```
Restart Nginx.

## Initialize the environment (once per machine)

```
cd /acme
wget https://raw.githubusercontent.com/matrey/acme-tiny-auto/master/acme-tiny-auto.sh
# wget https://gitee.com/matrey/acme-tiny-auto/raw/master/acme-tiny-auto.sh # (from China)
chmod +x acme-tiny-auto.sh
./acme-tiny-auto.sh
```

It will ask you to create a `config.sh` file, and offers the following template:
```
# Provider: either "letsencrypt" or "buypass". For buypass you must provide an email address.
ACMEPROVIDER=buypass
ACMECONTACTEMAIL=nobody@example.com

# This should be the webroot for challenges. If you don't rewrite URLs it should contain /.well-known/acme-challenge/ (and these folders should exist)
WELLKNOWNROOT=/acme/shared/.well-known/acme-challenge/

# (optional) This is the function to be called if at least one certificate has been changed (renew, renew-all only)
function apply_new_cert(){
  # SIGHUP nginx
  kill -HUP $( cat /run/nginx.pid )
}
```
Save these lines under `/acme/config.sh` and ensure `WELLKNOWNROOT` is correct (it should match the path configured in Nginx's default host). We will get back to `apply_new_cert` later.

Then we initialize the environment (download root certs from Let's Encrypt, download acme_tiny.py, etc.)
```
./acme-tiny-auto.sh init
# VENDORED=1 ./acme-tiny-auto.sh init # (from China)
```
Verify all went fine.

## Add one domain (for each new domain)

First we get the certificate for it (replace `example.com` by your (sub)domain)
```
cd /acme
./acme-tiny-auto.sh add example.com
```
If all goes well, we end up with:
* `/acme/domains/example.com/domain.crt` the signed certificate and intermediate from Let's Encrypt
* `/acme/domains/example.com/domain.key` the private key
* `/acme/domains/example.com/ocsp.crt` the bundle for OCSP stapling (root CA + intermediate)

Then we need to edit this host's Nginx configuration.

Go get proper settings from https://mozilla.github.io/server-side-tls/ssl-config-generator/ 
* select your server software and version (e.g. for Nginx it's common for the versions bundled with Linux distributions to be way older than what you can get from the official Nginx site)
* choose the level of client support you want. Usually "intermediate" is a good balance between security and client compatibility.
* be careful with HSTS, you might not want to use it at first (web browsers will refuse to use the http version of your site if HSTS is ever enabled, and it's not something you can fix. At a minimum, begin with a low caching duration, e.g. 1 day and change it later once you confirm everything works)

In the generated code, remember to edit:
* `ssl_certificate` set to `/acme/domains/example.com/domain.crt`
* `ssl_certificate_key` set to `/acme/domains/example.com/domain.key`
* `ssl_trusted_certificate` set to `/acme/domains/example.com/ocsp.crt`

Side note: for `ssl_dhparam` you can use `openssl dhparam -out /acme/dhparam.pem 2048` to generate the file under `/acme/dhparam.pem`

Restart Nginx and verify all is fine. 
You can use Qualys SSLTest service to verify the grade for your server: https://www.ssllabs.com/ssltest/


# Renewal management

## Automatically renew certificates

Remember to schedule a cronjob on `root` that calls `/acme/acme-tiny-auto.sh renew-all`.
e.g.
```
20 16 * * * /acme/acme-tiny-auto.sh renew-all
```

It will automatically renew certificates for all domains under `domains`, no more than 7 days before they expire. So it's not a problem to run it "often" (daily at 4:20pm in the example above).

We finally get back to the `apply_new_cert` function in `config.sh`. It will be called at the end of `renew-all` if any certificate has been renewed. The objective is to send a signal to the webserver to load the new certificate.
For Nginx, the following usually works well: `kill -HUP $( cat /run/nginx.pid )`

## Stop renewing certificates for a domain

To just let the current certificate expire, and not attempt to renew it, you can put an empty "do_not_renew" file in the domain folder. e.g.
```
touch /acme/domains/example.com/do_not_renew
```

