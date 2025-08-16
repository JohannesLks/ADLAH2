#!/bin/bash
set -euo pipefail

# =====================================
# Configuration
# =====================================
HIVE_CERTBOT_CONF="$(pwd)/hive/nginx/certbot.conf"
HIVE_CERTBOT_WEBROOT="/var/www/certbot"

# =====================================
# Helper Functions
# =====================================
log() { echo -e "\e[32m[CERTBOT]\e[0m $*"; }
warn() { echo -e "\e[33m[CERTBOT] \e[0m $*"; }
error() { echo -e "\e[31m[CERTBOT] \e[0m $*" >&2; }

# =====================================
# Validation
# =====================================
check_certbot() {
    if ! [ -x "$(command -v certbot)" ]; then
        log "Certbot not found. Installing..."
        sudo apt-get update
        sudo apt-get install -y certbot
    else
        log "Certbot is already installed."
    fi
}

# =====================================
# Certificate Generation
# =====================================
request_certificate() {
    log "Requesting Let's Encrypt certificate..."
    sudo certbot certonly --webroot --webroot-path=/var/www/certbot \
        -d adlah.dev --agree-tos --no-eff-email --non-interactive --register-unsafely-without-email
}

copy_certificates() {
    log "Copying certificate to Nginx directory..."
    local cert_path="$(pwd)/hive/nginx/certs/cert.pem"
    local key_path="$(pwd)/hive/nginx/certs/key.pem"

    sudo mkdir -p "$(pwd)/hive/nginx/certs/"
    sudo cp "/etc/letsencrypt/live/adlah.dev/fullchain.pem" "$cert_path"
    if [ $? -ne 0 ]; then
        error "Failed to copy certificate."
        return 1
    fi

    sudo cp "/etc/letsencrypt/live/adlah.dev/privkey.pem" "$key_path"
    if [ $? -ne 0 ]; then
        error "Failed to copy private key."
        return 1
    fi

    sudo chmod 644 "$cert_path" "$key_path"
    log "Certificate and key copied successfully."
}

start_temp_nginx() {
    log "Starting temporary Nginx container..."
    docker run -d --name temp-nginx -p 80:80 \
        -v "$HIVE_CERTBOT_CONF:/etc/nginx/conf.d/default.conf" \
        -v "$HIVE_CERTBOT_WEBROOT:/var/www/certbot" \
        nginx
}

stop_temp_nginx() {
    log "Stopping temporary Nginx container..."
    docker stop temp-nginx
    docker rm temp-nginx
}

restart_nginx_manually() {
    log "Configuration and certificates are in place."
    log "Please run 'docker compose -f hive/docker-compose.yml restart nginx' to apply the changes."
}

test_ssl() {
    log "Testing SSL configuration..."
    sleep 5 # Wait for nginx to restart
    docker run --rm --network="host" appropriate/curl --fail --silent --show-error -k https://localhost > /dev/null
}

# =====================================
# Main Execution
# =====================================
validate_installation() {
    log "Validating certificate installation..."
    local cert_path="$(pwd)/hive/nginx/certs/cert.pem"
    
    if [ ! -f "$cert_path" ]; then
        error "Certificate file not found at $cert_path"
        return 1
    fi

    log "Certificate validation successful."
}
main() {
    log "Starting Certbot SSL certificate generation..."
    check_certbot
    start_temp_nginx
    
    if ! request_certificate; then
        error "Failed to request certificate. Aborting."
        stop_temp_nginx
        return 1
    fi
    
    stop_temp_nginx
    
    if ! copy_certificates; then
        error "Failed to copy certificates. Aborting."
        return 1
    fi
    
    restart_nginx_manually
    log "Certbot setup completed successfully."
}

# Run main function
main "$@"