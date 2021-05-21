#!/bin/bash
DIR=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )

for pytry in python python3 python2; do
  if command -v "$pytry" &> /dev/null; then 
    PYTHONEXEC=$pytry
    break
  fi
done

if [[ -z "$PYTHONEXEC" ]]; then
  echo "Missing Python!" >&2
  exit 1
fi

# Set restrictive umask, but keep a copy of the old one to be able to reapply it when calling acme_tiny.py
UMASK=$( umask -S )
umask g=,o=

function write_log(){
  local MESSAGE
  local DT
  MESSAGE=$1
  DT=$( date --iso-8601=seconds )
  echo -e "time:${DT}\t${MESSAGE}" >> "$DIR/acme.log"
}

function noisy_fail(){
  echo "FAILED!" >&2
}
function noisy_write(){
  if [[ "$2" == "noisy" ]]; then
    echo "$1" >&2
  fi
}

# Keep track of the number of generated certificates, to see if it is needed to reload the webserver
NBRENEWED=0

# Helpers: certificates
# ---------------------

function is_cert(){
  local CERT
  CERT=$1
  openssl x509 -inform PEM -in "$CERT" -noout 2>/dev/null
  return $?
}
function is_cert_fingerprint(){ # SHA256, e.g. 25:84:7D:66:8E:...
  local CERT
  local FINGERPRINT
  CERT=$1
  FINGERPRINT=$2
  if [[ "$FINGERPRINT" == "" ]]; then
    return 1
  fi
  FG=$( openssl x509 -in "$CERT" -noout -sha256 -fingerprint | sed -e 's/^SHA256 Fingerprint=//' )
  if [[ "$FG" == "$FINGERPRINT" ]]; then
    return 0
  fi
  return 1
}
function is_domaincert_renewable(){
  local DOMAIN
  local EXPDATE
  local EXPTS
  local DIFFTS
  
  DOMAIN=$1

  EXPDATE=$( openssl x509 -enddate -noout -in "$DIR/domains/$DOMAIN/domain.crt" | sed -e 's/^notAfter=//' )
  EXPTS=$( date -u --date "$EXPDATE" +"%s" )
  DIFFTS=$(( ( EXPTS - $(date -u +"%s") ) / 86400 ))

  if [[ "$DIFFTS" -gt "7" ]]; then # more than 7 days to expiration: no need to renew
    return 1
  else
    return 0
  fi
}
function renew_domaincert(){
  local DOMAIN
  local NOISY
  DOMAIN=$1
  NOISY=$2
  
  # Check if we already have an account key
  if [[ ! -f "$DIR/account.key-tmp" ]]; then
    # Generate an account key
    generate_key "$DIR/account.key-tmp" 4096
  fi
  
  # Generate a new domain key
  generate_key "$DIR/domains/$DOMAIN/new.key" 2048

  # Generate CSR
  openssl req -new -sha256 -key "$DIR/domains/$DOMAIN/new.key" -subj "/CN=$DOMAIN" > "$DIR/domains/$DOMAIN/domain.csr"
  
  # Call acme_tiny
  umask "$UMASK"

  ARGSMORE=()
  if [[ "$NOISY" != "noisy" ]]; then
    ARGSMORE+=( --quiet )
  fi
  if [[ "$ACMEPROVIDER" == "buypass" ]]; then
    ARGSMORE+=( --contact "mailto:${ACMECONTACTEMAIL}" --directory-url 'https://api.buypass.com/acme/directory' )
  fi

  $PYTHONEXEC "$DIR/acme_tiny.py" --account-key "$DIR/account.key-tmp" --csr "$DIR/domains/$DOMAIN/domain.csr" --acme-dir "$WELLKNOWNROOT" "${ARGSMORE[@]}" > "$DIR/domains/$DOMAIN/new.crt"

  RETVAL=$?
  umask g=,o=
  if [[ "$RETVAL" -ne "0" ]]; then
    write_log "action:renew\tstatus:KO\tdomain:${DOMAIN}\terror:acme_tiny exited with code ${RETVAL}"
    noisy_write "acme_tiny.py exited with code ${RETVAL}!" "$NOISY"
    return 1
  fi

  # We should have the certificate + its intermediate in "$DIR/domains/$DOMAIN/new.crt"
  # Note that there might be several intermediates
  certs_int=()

  # Let's isolate the intermediates from the leaf cert
  for cert in $( cat "$DIR/domains/$DOMAIN/new.crt" | sed -e 's/^-----.*$/###/' | tr -d '\n\r\t ' | sed -e 's/#/\n/g' | grep -v '^$' ); do
    formatted_cert=$( echo -e "-----BEGIN CERTIFICATE-----\n${cert}\n-----END CERTIFICATE-----" | fold -w64 )
    is_intermediate=$( openssl x509 -in <( echo "${formatted_cert}" ) -noout -purpose | grep 'SSL client CA' | grep Yes | wc -l )
    if [[ "${is_intermediate}" -eq "1" ]]; then
      certs_int+=("${formatted_cert}")
    else
      cert_leaf=${formatted_cert}
    fi
  done

  # We need the root CA cert for OCSP stapling
  # Given that the OCSP bundle seems to act like a trust store, it should be fine if we pass several roots
  # We hardcode them as they are a very slow changing dimension

  certs_root=()

  # ISRG X1
  # https://letsencrypt.org/certs/isrgrootx1.pem (pem)
  certs_root+=('-----BEGIN CERTIFICATE-----
MIIFazCCA1OgAwIBAgIRAIIQz7DSQONZRGPgu2OCiwAwDQYJKoZIhvcNAQELBQAw
TzELMAkGA1UEBhMCVVMxKTAnBgNVBAoTIEludGVybmV0IFNlY3VyaXR5IFJlc2Vh
cmNoIEdyb3VwMRUwEwYDVQQDEwxJU1JHIFJvb3QgWDEwHhcNMTUwNjA0MTEwNDM4
WhcNMzUwNjA0MTEwNDM4WjBPMQswCQYDVQQGEwJVUzEpMCcGA1UEChMgSW50ZXJu
ZXQgU2VjdXJpdHkgUmVzZWFyY2ggR3JvdXAxFTATBgNVBAMTDElTUkcgUm9vdCBY
MTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAK3oJHP0FDfzm54rVygc
h77ct984kIxuPOZXoHj3dcKi/vVqbvYATyjb3miGbESTtrFj/RQSa78f0uoxmyF+
0TM8ukj13Xnfs7j/EvEhmkvBioZxaUpmZmyPfjxwv60pIgbz5MDmgK7iS4+3mX6U
A5/TR5d8mUgjU+g4rk8Kb4Mu0UlXjIB0ttov0DiNewNwIRt18jA8+o+u3dpjq+sW
T8KOEUt+zwvo/7V3LvSye0rgTBIlDHCNAymg4VMk7BPZ7hm/ELNKjD+Jo2FR3qyH
B5T0Y3HsLuJvW5iB4YlcNHlsdu87kGJ55tukmi8mxdAQ4Q7e2RCOFvu396j3x+UC
B5iPNgiV5+I3lg02dZ77DnKxHZu8A/lJBdiB3QW0KtZB6awBdpUKD9jf1b0SHzUv
KBds0pjBqAlkd25HN7rOrFleaJ1/ctaJxQZBKT5ZPt0m9STJEadao0xAH0ahmbWn
OlFuhjuefXKnEgV4We0+UXgVCwOPjdAvBbI+e0ocS3MFEvzG6uBQE3xDk3SzynTn
jh8BCNAw1FtxNrQHusEwMFxIt4I7mKZ9YIqioymCzLq9gwQbooMDQaHWBfEbwrbw
qHyGO0aoSCqI3Haadr8faqU9GY/rOPNk3sgrDQoo//fb4hVC1CLQJ13hef4Y53CI
rU7m2Ys6xt0nUW7/vGT1M0NPAgMBAAGjQjBAMA4GA1UdDwEB/wQEAwIBBjAPBgNV
HRMBAf8EBTADAQH/MB0GA1UdDgQWBBR5tFnme7bl5AFzgAiIyBpY9umbbjANBgkq
hkiG9w0BAQsFAAOCAgEAVR9YqbyyqFDQDLHYGmkgJykIrGF1XIpu+ILlaS/V9lZL
ubhzEFnTIZd+50xx+7LSYK05qAvqFyFWhfFQDlnrzuBZ6brJFe+GnY+EgPbk6ZGQ
3BebYhtF8GaV0nxvwuo77x/Py9auJ/GpsMiu/X1+mvoiBOv/2X/qkSsisRcOj/KK
NFtY2PwByVS5uCbMiogziUwthDyC3+6WVwW6LLv3xLfHTjuCvjHIInNzktHCgKQ5
ORAzI4JMPJ+GslWYHb4phowim57iaztXOoJwTdwJx4nLCgdNbOhdjsnvzqvHu7Ur
TkXWStAmzOVyyghqpZXjFaH3pO3JLF+l+/+sKAIuvtd7u+Nxe5AW0wdeRlN8NwdC
jNPElpzVmbUq4JUagEiuTDkHzsxHpFKVK7q4+63SM1N95R1NbdWhscdCb+ZAJzVc
oyi3B43njTOQ5yOf+1CceWxG1bQVs5ZufpsMljq4Ui0/1lvh+wjChP4kqKOJ2qxq
4RgqsahDYVvTH9w7jXbyLeiNdd8XM2w9U/t7y0Ff/9yi0GE44Za4rF2LN9d11TPA
mRGunUHBcnWEvgJBQl9nJEiU0Zsnvgc/ubhPgXRR4Xq37Z0j4r7g1SgEEzwxA57d
emyPxgcYxn/eR44/KJ4EBs+lVDR3veyJm+kXQ99b21/+jh5Xos1AnX5iItreGCc=
-----END CERTIFICATE-----')

  # ISRG X2
  # https://letsencrypt.org/certs/isrg-root-x2.pem (pem)
  certs_root+=('-----BEGIN CERTIFICATE-----
MIICGzCCAaGgAwIBAgIQQdKd0XLq7qeAwSxs6S+HUjAKBggqhkjOPQQDAzBPMQsw
CQYDVQQGEwJVUzEpMCcGA1UEChMgSW50ZXJuZXQgU2VjdXJpdHkgUmVzZWFyY2gg
R3JvdXAxFTATBgNVBAMTDElTUkcgUm9vdCBYMjAeFw0yMDA5MDQwMDAwMDBaFw00
MDA5MTcxNjAwMDBaME8xCzAJBgNVBAYTAlVTMSkwJwYDVQQKEyBJbnRlcm5ldCBT
ZWN1cml0eSBSZXNlYXJjaCBHcm91cDEVMBMGA1UEAxMMSVNSRyBSb290IFgyMHYw
EAYHKoZIzj0CAQYFK4EEACIDYgAEzZvVn4CDCuwJSvMWSj5cz3es3mcFDR0HttwW
+1qLFNvicWDEukWVEYmO6gbf9yoWHKS5xcUy4APgHoIYOIvXRdgKam7mAHf7AlF9
ItgKbppbd9/w+kHsOdx1ymgHDB/qo0IwQDAOBgNVHQ8BAf8EBAMCAQYwDwYDVR0T
AQH/BAUwAwEB/zAdBgNVHQ4EFgQUfEKWrt5LSDv6kviejM9ti6lyN5UwCgYIKoZI
zj0EAwMDaAAwZQIwe3lORlCEwkSHRhtFcP9Ymd70/aTSVaYgLXTWNLxBo1BfASdW
tL4ndQavEi51mI38AjEAi/V3bNTIZargCyzuFJ0nN6T5U6VR5CmD1/iQMVtCnwr1
/q4AaOeMSQ+2b1tbFfLn
-----END CERTIFICATE-----')

  # Buypass
  # http://crt.buypass.no/crt/BPClass2Rot.cer (der)
  certs_root+=('-----BEGIN CERTIFICATE-----
MIIFWTCCA0GgAwIBAgIBAjANBgkqhkiG9w0BAQsFADBOMQswCQYDVQQGEwJOTzEd
MBsGA1UECgwUQnV5cGFzcyBBUy05ODMxNjMzMjcxIDAeBgNVBAMMF0J1eXBhc3Mg
Q2xhc3MgMiBSb290IENBMB4XDTEwMTAyNjA4MzgwM1oXDTQwMTAyNjA4MzgwM1ow
TjELMAkGA1UEBhMCTk8xHTAbBgNVBAoMFEJ1eXBhc3MgQVMtOTgzMTYzMzI3MSAw
HgYDVQQDDBdCdXlwYXNzIENsYXNzIDIgUm9vdCBDQTCCAiIwDQYJKoZIhvcNAQEB
BQADggIPADCCAgoCggIBANfHXvfBB9R3+0Mh9PT1aeTuMgHbo4Yf5FkNuud1g1Lr
6hxhFUi7HQfKjK6w3Jad6sNgkoaCKHOcVgb/S2TwDCo3SbXlzwx87vFKu3MwZfPV
L4O2fuPn9Z6rYPnT8Z2SdIrkHJasW4DptfQxh6NR/Md+oW+OU3fUl8FVM5I+GC91
1K2GScuVr1QGbNgGE41b/+EmGVnAJLqBcXmQRFBoJJRfuLMR8SlBYaNByyM21cHx
MlAQTn/0hpPshNOOvEu/XAFOBz3cFIqUCqTqc/sLUegTBxj6DvEr0VQVfTzh97QZ
QmdiXnfgolXsttlpF9U6r0TtSsWe5HonfOV116rLJeffawrbD02TTqigzXsu8lkB
arcNuAeBfos4GzjmCleZPe4h6KP1DBbdi+w0jpwqHAAVF41og9JwnxgIzRFo1clr
Us3ERo/ctfPYV3Me6ZQ5BL/T3jjetFPsaRyifsSP5BtwrfKi+fv3FmRmaZ9JUaLi
FRhnBkp/1Wy1TbMz4GHrXb7pmA8y1x1LPC5aAVKRCfLf6o3YBkBjqhHk/sM3nhRS
P/TizPJhk9H9Z2vXUq6/aKtAQ6BXNVN48FP4YUIHZMbXb5tMOA1jrGKvNouicwoN
9SG9dKpN6nIDSdvHXx1iY8f93ZHsM+71bbRuMGjeyNYmsHVee7QHIJihdjK4TWxP
AgMBAAGjQjBAMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFMmAd+BikoL1Rpzz
uvdMw964o605MA4GA1UdDwEB/wQEAwIBBjANBgkqhkiG9w0BAQsFAAOCAgEAU18h
9bqwOlI5LJKwbADJ784g7wbylp7ppHR/ehb8t/W2+xUbP6umwHJdELFx7rxP462s
A20ucS6vxOOto70MEae0/0qyexAQH6dXQbLArvQsWdZHEIjzIVEpMMpghq9Gqx3t
OluwlN5E40EIosHsHdb9T7bWR9AUC8rmyrV7d35BH16Dx7aMOZawP5aBQW9gkOLo
+fsicdl9sz1Gv7SEr5AcD48Saq/v7h56rgJKihcrdv6sVIkkLE8/trKnToyokZf7
KcZ7XC25y2a2t6hbElGFtQl+Ynhw/qlqYLYdDnkM/crqJIByw5c/8nerQyIKx+u2
DISCLIBrQYoIwOula9+ZEsuK1V6ADJHgJgg2SMX6OBE1/yWDLfJ6v9r9jv6ly0Us
H8SIU653DtmadsWOLB2jutXsMq7Aqqz30XpN69QH4kj3Io6wpJ9qzo6ysmD0oyLQ
I+uUWnpp3Q+/QFesa1lQ2aOZ4W7+jQF5JyMV3pKdewlNWudLSDBaGOYKbeaP4NK7
5t98biGCwWg5TbSYWGZizEqQXsP6JwSxeRV0mcy+rSDeJmAc61ZRpqPq5KM/p/9h
3PFaTWwyI0PurKju7koSCTxdccK+efrCh2gdC/1cacwG0Jp9VJkqyTkaGa9LKkPz
Y11aWOIv4x3kqdbQCtCev9eBCfHJxyYNrJgWVqA=
-----END CERTIFICATE-----')

  # Verify the chain
  openssl verify -CAfile <( for cert in "${certs_root[@]}"; do echo "$cert"; echo; done ) -untrusted <( for cert in "${certs_int[@]}"; do echo "$cert"; echo; done ) <( echo "${cert_leaf}" ) > /dev/null 2>/dev/null
  if [[ "$?" -ne 0 ]]; then
    write_log "action:renew\tstatus:KO\tdomain:${DOMAIN}\terror:bad chain"
    noisy_write "Failed to validate the CA / int / leaf certificate chain" "$NOISY"
    return 1
  fi

  # If we are here, we can make the OCSP bundle
  ( for cert in "${certs_root[@]}"; do echo "$cert"; echo; done; for cert in "${certs_int[@]}"; do echo "$cert"; echo; done ) > "$DIR/domains/$DOMAIN/ocsp.crt"

  # And replace the current private key and certificate
  cat "$DIR/domains/$DOMAIN/new.key" > "$DIR/domains/$DOMAIN/domain.key"
  cat "$DIR/domains/$DOMAIN/new.crt" > "$DIR/domains/$DOMAIN/domain.crt"
  rm -f "$DIR/domains/$DOMAIN/domain.csr"
  write_log "action:renew\tstatus:OK\tdomain:${DOMAIN}"
  
  # Increment the counter of renewed certificates
  NBRENEWED=$(( NBRENEWED + 1 ))

  return 0
}

# Helpers: RSA keys
# -----------------

function is_key(){
  local RSA
  RSA=$1
  openssl rsa -inform PEM -in "$RSA" -noout 2>/dev/null
  return $?
}
function generate_key(){
  local TARGET
  local BITS
  TARGET=$1
  BITS=$2
  openssl genrsa "${BITS}" 2>/dev/null > "${TARGET}.tmp"
  is_key "${TARGET}.tmp" || exit 10
  mv "${TARGET}.tmp" "$TARGET"
}

# Helpers: external downloads
# ---------------------------

function download_acme_tiny(){
  local TARGET
  local SHASUM
  TARGET=$1
  local DLURL=https://raw.githubusercontent.com/diafygi/acme-tiny/58752c527c9345d23a771d2a93f729aaa8fe7712/acme_tiny.py
  if [[ "${VENDORED:-}" -eq 1 ]]; then
    DLURL=https://gitee.com/matrey/acme-tiny-auto/raw/1d4c8a8bc25c5290f8566ceebfc8a559493067f5/vendor/acme_tiny.py
  fi
  curl -Ss "$DLURL" -o "${TARGET}.tmp"
  SHASUM=$( sha256sum "${TARGET}.tmp" | cut -f1 -d' ' )
  if [[ "$SHASUM" != "644c73397d45b95ddc74eb793d8fa8a7ffb49784f01d1c04d546d7c653b9a4f1" ]]; then
    exit 10
  fi

  # Patch the code to make it work with buypass
  sed -i 's@^    reg_payload = {"termsOfServiceAgreed": True}$@    # Patched by acme_tiny_auto according to https://github.com/diafygi/acme-tiny/issues/241\n    reg_payload = {"termsOfServiceAgreed": True}\n    if contact is not None:\n        reg_payload = {"termsOfServiceAgreed": True, "contact": contact}@' "${TARGET}.tmp"

  mv "${TARGET}.tmp" "$TARGET"
}

# Macro functions (remark: they exit)
# -----------------------------------

function do_init(){
  trap noisy_fail EXIT

  # Get acme-tiny
  echo "Download acme_tiny.py..." >&2
  download_acme_tiny "$DIR/acme_tiny.py"

  # Create the folder for domains configuration
  mkdir -p "$DIR/domains/"

  echo "SUCCESS!" >&2
  trap - EXIT
  exit 0
}
function do_add(){
  local DOMAIN
  DOMAIN=$1
  trap noisy_fail EXIT

  # Create the folder if needed
  mkdir -p "$DIR/domains/$DOMAIN"

  # Get the certificate
  echo "Request certificate..." >&2
  renew_domaincert "$DOMAIN" "noisy" || exit 10
  
  echo "SUCCESS! (remark: we did NOT notify the webserver of the new certificate)" >&2
  trap - EXIT
  exit 0
}
function do_user_refresh(){
  if [[ "$NBRENEWED" -gt "0" ]]; then # At least 1 certificate renewed
    type -t "apply_new_cert" 2>/dev/null | grep -q 'function' # grep -q returns 0 if there is a match
    # shellcheck disable=SC2181
    if [[ "$?" -eq "0" ]]; then
      apply_new_cert
      RETVAL="$?"
      if [[ "$RETVAL" -eq "0" ]]; then
        write_log "action:reload\tstatus:OK"
      else
        write_log "action:reload\tstatus:KO\tcode:${RETVAL}"
      fi
      exit "$RETVAL"
    fi
  fi
  exit 0
}

# Main program
# ------------
function print_usage(){
  echo "Usage: $0 [init | add [domain]| renew [domain] | force-renew [domain] | renew-all ]" >&2
  echo "Note that renew and renew-all are quiet by default, and will only write to STDERR (and return > 0) on failure." >&2
}

# Configuration file validation
if [[ ! -f "$DIR/config.sh" ]]; then
  echo "Missing config.sh! You must create it before using this script." >&2
  cat <<- "EOF"
Sample file:
-----------------------------------
# Provider: either "letsencrypt" or "buypass". For buypass you must also provide an email address (not used with letsencrypt).
ACMEPROVIDER=buypass
ACMECONTACTEMAIL=nobody@example.com

# This should be the webroot for challenges. If you don't rewrite URLs it should contain /.well-known/acme-challenge/ (and these folders should exist)
WELLKNOWNROOT=/acme/shared/.well-known/acme-challenge/

# (optional) This is the function to be called if at least one certificate has been changed (renew, renew-all only)
function apply_new_cert(){
  # SIGHUP nginx
  kill -HUP $( cat /run/nginx.pid )
}
-----------------------------------
EOF

  exit 1
fi
# shellcheck source=/dev/null
source "$DIR/config.sh"
if [[ ! -d "$WELLKNOWNROOT" ]]; then
  echo "The WELLKNOWNROOT path listed in config.sh does not exist!" >&2
  exit 1
fi
if [[ "${ACMEPROVIDER:-}" == "letsencrypt" ]]; then
  :
elif [[ "${ACMEPROVIDER:-}" == "buypass" ]]; then
  if [[ -z "${ACMECONTACTEMAIL}" || "${ACMECONTACTEMAIL}" == "nobody@example.com" ]]; then
    echo "For buypass you must provide a valid email address!" >&2
    exit 1
  fi
else
  echo "You must configure ACMEPROVIDER=buypass or ACMEPROVIDER=letsencrypt" >&2
  exit 1
fi

# Command line parsing
case "$1" in

  ## "Quiet" commands (good for cron usage) ##
  
  "renew")
    # Empty domain
    if [[ -z "$2" ]]; then
      echo "Domain missing!" >&2
      print_usage
      exit 1
    fi
    # Incorrect domain (doesn't exist)
    if [[ ! -d "${DIR}/domains/$2" ]]; then
      echo "Configuration folder for this domain does not exist!" >&2
      exit 1
    fi
    
    write_log "action:renew\tdomain:$2\ttype:ping"
    
    # We expect to have an existing certificate (would be weird otherwise... not a normal case for automatic jobs)
    is_cert "$DIR/domains/$2/domain.crt" || exit 20
    # Check if the certificate is still valid long enough
    is_domaincert_renewable "$2" || exit 0
    # If not, attempt to renew it
    renew_domaincert "$2" || exit 10
    
    # Call user function if needed
    do_user_refresh
    ;;
    
  "renew-all")
    # Find all domains
    OLDIFS=$IFS
    IFS=$'\n'
    DOMS=($( find "${DIR}/domains/" -maxdepth 1 -type d -exec basename {} \; | grep -v ^domains$ ))
    IFS=$OLDIFS
  
    write_log "action:renew-all\ttype:ping"
    
    # For each domain check if there is a do_not_renew file
    for DOM in "${DOMS[@]}"; do
      if [[ ! -f "$DIR/domains/$DOM/do_not_renew" ]]; then
      
        # We expect to have an existing certificate (would be weird otherwise... not a normal case for automatic jobs)
        is_cert "$DIR/domains/$DOM/domain.crt" || continue
        # Check if the certificate is still valid long enough
        is_domaincert_renewable "$DOM" || continue
        # If not, attempt to renew it
        renew_domaincert "$DOM"

      fi
    done
    
    # Call user function if needed
    do_user_refresh
    ;;
    
  ## "Noisy" commands (for humans) ##
  
  "init")
    # acme_tiny.py already exists
    if [[ -f "$DIR/acme_tiny.py" ]]; then
      echo "Already done!" >&2
      exit 1
    fi

    do_init
    ;;
    
  "add")
    # Empty domain
    if [[ -z "$2" ]]; then
      echo "Domain missing!" >&2
      print_usage
      exit 1
    fi
    # Incorrect domain (already exists)
    if [[ -d "${DIR}/domains/$2" ]]; then
      echo "Configuration folder for this domain already exists!" >&2
      exit 1
    fi
    
    do_add "$2"
    ;;

  "force-renew")
    # Empty domain
    if [[ -z "$2" ]]; then
      echo "Domain missing!" >&2
      print_usage
      exit 1
    fi
    # Incorrect domain (doesn't exist)
    if [[ ! -d "${DIR}/domains/$2" ]]; then
      echo "Configuration folder for this domain does not exist!" >&2
      exit 1
    fi
    
    do_add "$2"
    ;;
    
  "help")
    print_usage
    exit 0
    ;;
    
  *)
    echo "Missing or invalid command!" >&2
    print_usage
    exit 1
    ;;
esac
