#!/bin/bash
DIR=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )

umask 077 # Restrict all created files to this user

function noisy_fail(){
  echo "FAILED!" >&2
}
function noisy_write(){
  if [[ "$2" == "noisy" ]]; then
    echo "$1" >&2
  fi
}

# Helpers: certificates
# ---------------------

function is_cert(){
  local CERT=$1
  openssl x509 -inform PEM -in "$CERT" -noout 2>/dev/null
  return $?
}
function is_cert_fingerprint(){ # SHA256, e.g. 25:84:7D:66:8E:...
  local CERT=$1
  local FINGERPRINT=$2
  if [[ "$FINGERPRINT" == "" ]]; then
    return 1
  fi
  FG=$( openssl x509 -in "$CERT" -noout -sha256 -fingerprint | sed -e 's/^SHA256 Fingerprint=//' )
  if [[ "$FG" == "$FINGERPRINT" ]]; then
    return 0
  fi
  return 1
}
function is_cert_renewable(){
  local DOMAIN=$1

  local EXPDATE=$( openssl x509 -enddate -noout -in "$DIR/domains/$DOMAIN/domain.crt" | sed -e 's/^notAfter=//' )
  local EXPTS=$( date -u --date "$EXPDATE" +"%s" )
  local DIFFTS=$(( ( EXPTS - $(date -u +"%s") ) / 86400 ))

  if [[ "$DIFFTS" -gt "7" ]]; then # more than 7 days to expiration: no need to renew
    return 1
  else
    return 0
  fi
}
function renew_cert(){
  local DOMAIN=$1
  local NOISY=$2

  # Call acme_tiny
  if [[ "$NOISY" == "noisy" ]]; then
    python acme_tiny.py --account-key "$DIR/account.key" --csr "$DIR/domains/$DOMAIN/domain.csr" --acme-dir "$WELLKNOWNROOT" > "$DIR/domains/$DOMAIN/new.crt"
  else
    python acme_tiny.py --quiet --account-key "$DIR/account.key" --csr "$DIR/domains/$DOMAIN/domain.csr" --acme-dir "$WELLKNOWNROOT" > "$DIR/domains/$DOMAIN/new.crt"
  fi
  RETVAL=$?
  if [[ "$RETVAL" -ne "0" ]]; then
    noisy_write "acme_tiny.py exited with code ${RETVAL}!" "$NOISY"
    return 1
  fi

  # Verify the certificate is valid
  openssl x509 -inform PEM -in "$DIR/domains/$DOMAIN/new.crt" -noout 2>/dev/null
  if [[ "$?" -ne "0" ]]; then
    noisy_write "The payload we got back is not a certificate!" "$NOISY"
    return 1
  fi

  # Also that it is issued by the expected intermediate
  openssl verify -untrusted "$DIR/intermediate.crt" "$DIR/domains/$DOMAIN/new.crt" >/dev/null
  if [[ "$?" -ne "0" ]]; then # This is not the intermediate we expected!
    noisy_write "The certificate we got back is not signed by the expected intermediate!" "$NOISY"
    return 1
  fi

  # If all is good, we can replace the current certificate
  cat "$DIR/domains/$DOMAIN/new.crt" "$DIR/intermediate.crt" > "$DIR/domains/$DOMAIN/domain.crt"

  return 0
}

# Helpers: external downloads
# ---------------------------

function download_cert(){ 
  local URL=$1
  local FINGERPRINT=$2
  local TARGET=$3
  curl -Ss "$URL" > "${TARGET}.tmp"
  is_cert "${TARGET}.tmp" || exit 10
  is_cert_fingerprint "${TARGET}.tmp" "$FINGERPRINT" || exit 10
  mv "${TARGET}.tmp" "$TARGET"
}
function download_acme_tiny(){
  local TARGET=$1
  curl -Ss "https://raw.githubusercontent.com/diafygi/acme-tiny/master/acme_tiny.py" > "${TARGET}.tmp"
  local SHASUM=$( sha256sum "${TARGET}.tmp" | cut -f1 -d' ' )
  if [[ "$SHASUM" != "bcd7cb56c280543c929cb4b7b2d1ed2d7ebabdae74fedc96b6a63f218c0b8ace" ]]; then
    exit 10
  fi
  mv "${TARGET}.tmp" "$TARGET"
}

# Helpers: RSA keys
# -----------------

function is_key(){
  local RSA=$1
  openssl rsa -inform PEM -in "$RSA" -noout 2>/dev/null
  return $?
}
function generate_key(){
  local TARGET=$1
  openssl genrsa 4096 2>/dev/null > "${TARGET}.tmp"
  is_key "${TARGET}.tmp" || exit 10
  mv "${TARGET}.tmp" "$TARGET"
}

# Macro functions (remark: they exit)
# -----------------------------------

function do_init(){
  trap noisy_fail EXIT

  # Get root and intermediate certificates
  echo "Download root certificate..." >&2
  download_cert "https://letsencrypt.org/certs/isrgrootx1.pem.txt" "96:BC:EC:06:26:49:76:F3:74:60:77:9A:CF:28:C5:A7:CF:E8:A3:C0:AA:E1:1A:8F:FC:EE:05:C0:BD:DF:08:C6" "$DIR/ca.crt"
  echo "Download intermediate certificate..." >&2
  download_cert "https://letsencrypt.org/certs/lets-encrypt-x3-cross-signed.pem.txt" "25:84:7D:66:8E:B4:F0:4F:DD:40:B1:2B:6B:07:40:C5:67:DA:7D:02:43:08:EB:6C:2C:96:FE:41:D9:DE:21:8D" "$DIR/intermediate.crt"

  # Make bundle for OCSP stapling
  cat "$DIR/ca.crt" "$DIR/intermediate.crt" > "$DIR/ocsp.crt"

  # Get acme-tiny
  echo "Download acme_tiny.py..." >&2
  download_acme_tiny "$DIR/acme_tiny.py"

  # Generate an account key
  echo "Generate account key..." >&2
  generate_key "$DIR/account.key"

  # Create the folder for domains configuration
  mkdir -p "$DIR/domains/"

  echo "SUCCESS!" >&2
  trap - EXIT
  exit 0
}
function do_add(){
  local DOMAIN=$1
  trap noisy_fail EXIT

  # Create the folder
  mkdir -p "$DIR/domains/$DOMAIN"

  # Generate domain key
  echo "Generate domain key..." >&2
  generate_key "$DIR/domains/$DOMAIN/domain.key"

  # Generate CSR
  echo "Generate CSR..." >&2
  openssl req -new -sha256 -key "$DIR/domains/$DOMAIN/domain.key" -subj "/CN=$DOMAIN" > "$DIR/domains/$DOMAIN/domain.csr"

  # Get the certificate
  echo "Request certificate..." >&2
  renew_cert "$DOMAIN" "noisy" || exit 10
  
  echo "SUCCESS!" >&2
  trap - EXIT
  exit 0
}
function do_forcerenew(){
  local DOMAIN=$1
  trap noisy_fail EXIT
  
  # Get the certificate
  echo "Request certificate..." >&2
  renew_cert "$DOMAIN" "noisy" || exit 10
  
  echo "SUCCESS!" >&2
  trap - EXIT
  exit 0
}
function do_autorenew(){
  local DOMAIN=$1

  # We expect to have an existing certificate (would be weird otherwise... not a normal case for automatic jobs)
  is_cert "$DOMAIN" || exit 20

  # Check if the certificate is still valid long enough
  is_cert_renewable "$DOMAIN" || exit 0

  # If not, attempt to renew it
  renew_cert "$DOMAIN" || exit 10
}

# Main program
# ------------
function print_usage(){
  echo "Usage: $0 [init | add <domain> | renew <domain> | force-renew <domain> | renew-all ]" >&2
}

# Configuration file validation
if [[ ! -f "$DIR/config.sh" ]]; then
  echo "Missing config.sh! You must create it before using this script." >&2
  echo -e "\nSample file:\n-----------------------------------\n# This should be the webroot for challenges. If you don't rewrite URLs it should contain /.well-known/acme-challenge/ (and these folders should exist)\nWELLKNOWNROOT=/www/challenges/shared/.well-known/acme-challenge/\n\n# This is the function to be called if at least one certificate has been changed\nfunction apply_new_cert(){\n  # SIGHUP nginx\n  kill -HUP \$( cat /run/nginx.pid )\n}\n-----------------------------------\n"
  exit 1
fi
source "$DIR/config.sh"
if [[ ! -d "$WELLKNOWNROOT" ]]; then
  echo "The WELLKNOWNROOT path listed in config.sh does not exist!" >&2
  exit 1
fi
type -t "apply_new_cert" 2>/dev/null | grep -q 'function'
if [[ "$?" -ne "0" ]]; then
  echo "There is no apply_new_cert function in config.sh!" >&2
  exit 1
fi

#TODO: at the end of any operation that generated a (valid) cert, we should call the user function to apply the changes
#TODO: make the user function optional?

# Command line parsing
case "$1" in

  # "Quiet" commands (good for cron usage)
  #TODO: trap EXIT and call a (optional) user defined function for alerting on failure
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
    
    do_auto_renew "$2"
    ;;
    
  "renew-all")
    echo "" 
    #TODO 
    # Idea is to list all folders under $DIR/domains and call the "renew" step on them
    # On failure it will just exit and leave the job half done (it's a feature!)
    ;;
    
  # "Noisy" commands (for humans)
  
  "init") 
    # Account key already exists
    if [[ -f "$DIR/account.key" ]]; then
      echo "You already have an account key!" >&2
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
    
    do_forcerenew "$2"
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
