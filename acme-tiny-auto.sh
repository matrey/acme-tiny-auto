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

  # Let's isolate the intermediate
  for cert in $( cat "$DIR/domains/$DOMAIN/new.crt" | sed -e 's/^-----.*$/###/' | tr -d '\n\r\t ' | sed -e 's/#/\n/g' | grep -v '^$' ); do
    is_intermediate=$( openssl x509 -in <( echo -e "-----BEGIN CERTIFICATE-----\n${cert}\n-----END CERTIFICATE-----" ) -noout -purpose | grep 'SSL client CA' | grep Yes | wc -l )
    if [[ "${is_intermediate}" -eq "1" ]]; then
      cert_int=${cert}
    else
      cert_leaf=${cert}
    fi
  done

  # Get root cert from intermediate's CA Issuers
  root_url=$( openssl x509 -in <( echo -e "-----BEGIN CERTIFICATE-----\n${cert_int}\n-----END CERTIFICATE-----" ) -text -noout | grep 'CA Issuers' | sed -e 's/^.*URI://' )
  if [[ "${root_url}" != "" ]]; then
    # Assume certificate format from extension
    root_format=$( echo "${root_url}" | tr -d '\r\n\t '| tail -c 3 )
  else
    # No CA Issuers (e.g. Buypass), need to find the root another way, based on issuer CN
    int_issuer=$( openssl x509 -in <( echo -e "-----BEGIN CERTIFICATE-----\n${cert_int}\n-----END CERTIFICATE-----" ) -issuer -noout | sed -e 's/^issuer= //' )
    if [[ "${int_issuer}" == "/C=NO/O=Buypass AS-983163327/CN=Buypass Class 2 Root CA" ]]; then
      root_url="http://crt.buypass.no/crt/BPClass2Rot.cer"
      root_format=der
    else
      write_log "action:renew\tstatus:KO\tdomain:${DOMAIN}\terror:unknown root"
      noisy_write "Failed to identify the location of the root certificate" "$NOISY"
      return 1
    fi
  fi

  # TODO: only supports PKCS7 as currently used by DST root
  if [[ "${root_format:0:2}" == "p7" ]]; then # convert from PKCS7
    cert_root=$( openssl pkcs7 -inform der -in <( curl -Ss "${root_url}" ) -print_certs | grep -v -e '^subject' -e '^issuer' )
  elif [[ "${root_format}" == "der" ]]; then # need der to pem
    cert_root=$( openssl x509 -inform der -in <( curl -Ss "${root_url}" ) )
  elif [[ "${root_format}" == "pem" ]]; then # ready to use pem
    cert_root=$( openssl x509 -in <( curl -Ss "${root_url}" ) )
  else
    write_log "action:renew\tstatus:KO\tdomain:${DOMAIN}\terror:bad root"
    noisy_write "Failed to identify the format of the root certificate" "$NOISY"
    return 1
  fi

  # Verify the chain
  openssl verify -CAfile <( echo "${cert_root}" ) -untrusted <( echo -e "-----BEGIN CERTIFICATE-----\n${cert_int}\n-----END CERTIFICATE-----" ) <( echo -e "-----BEGIN CERTIFICATE-----\n${cert_leaf}\n-----END CERTIFICATE-----" ) > /dev/null 2>/dev/null
  if [[ "$?" -ne 0 ]]; then
    write_log "action:renew\tstatus:KO\tdomain:${DOMAIN}\terror:bad chain"
    noisy_write "Failed to validate the CA / int / leaf certificate chain" "$NOISY"
    return 1
  fi

  # If we are here, we can make the OCSP bundle
  openssl x509 -in <( echo "${cert_root}" ) > "$DIR/domains/$DOMAIN/ocsp.crt"
  openssl x509 -in <( echo -e "-----BEGIN CERTIFICATE-----\n${cert_int}\n-----END CERTIFICATE-----" ) >> "$DIR/domains/$DOMAIN/ocsp.crt"

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
  curl -Ss "https://raw.githubusercontent.com/diafygi/acme-tiny/58752c527c9345d23a771d2a93f729aaa8fe7712/acme_tiny.py" -o "${TARGET}.tmp"
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
