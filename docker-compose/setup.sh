#!/usr/bin/env bash

BASE_DIR=$PWD

# Function to find the docker-compose file
find_docker_compose_file() {
    if [ -f "$BASE_DIR/docker-compose.yml" ]; then
        DOCKER_COMPOSE_FILE="$BASE_DIR/docker-compose.yml"
    elif [ -f "$BASE_DIR/docker-compose.yaml" ]; then
        DOCKER_COMPOSE_FILE="$BASE_DIR/docker-compose.yaml"
    else
        DOCKER_COMPOSE_FILE="$BASE_DIR/docker-compose.yml"
    fi
}

# Function to create a backup of the existing docker-compose file
create_backup() {
    if [ -f "$DOCKER_COMPOSE_FILE" ]; then
        local timestamp=$(date "+%Y-%m-%d_%H-%M-%S")
        local backup_file="${DOCKER_COMPOSE_FILE%.yml}_backup_${timestamp}.yml"
        cp "$DOCKER_COMPOSE_FILE" "$backup_file"
        echo "Backup created: $backup_file"
    fi
}

# Function to read existing values from docker-compose file
read_existing_values() {
    find_docker_compose_file

    if [ -f "$DOCKER_COMPOSE_FILE" ]; then
        echo "Reading existing values from $DOCKER_COMPOSE_FILE..."
        
        # Using grep, sed, and head to extract only the first occurrence of each value
        ADMIN_ACCESS_ID=$(grep 'ADMIN_ACCESS_ID=' "$DOCKER_COMPOSE_FILE" | head -n1 | sed 's/.*ADMIN_ACCESS_ID=//' | tr -d "'" | tr -d '"' | tr -d ' ')
        ADMIN_ACCESS_KEY=$(grep 'ADMIN_ACCESS_KEY=' "$DOCKER_COMPOSE_FILE" | head -n1 | sed 's/.*ADMIN_ACCESS_KEY=//' | tr -d "'" | tr -d '"' | tr -d ' ')
        BASTION_ACCESS_ID=$(grep 'PRIVILEGED_ACCESS_ID=' "$DOCKER_COMPOSE_FILE" | head -n1 | sed 's/.*PRIVILEGED_ACCESS_ID=//' | tr -d "'" | tr -d '"' | tr -d ' ')
        BASTION_ACCESS_KEY=$(grep 'PRIVILEGED_ACCESS_KEY=' "$DOCKER_COMPOSE_FILE" | head -n1 | sed 's/.*PRIVILEGED_ACCESS_KEY=//' | tr -d "'" | tr -d '"' | tr -d ' ')
        SSO_ACCESS_ID=$(grep 'ALLOWED_ACCESS_IDS=' "$DOCKER_COMPOSE_FILE" | head -n1 | sed 's/.*ALLOWED_ACCESS_IDS=//' | tr -d "'" | tr -d '"' | tr -d ' ' | cut -d',' -f1)
        AKEYLESS_URL=$(grep 'AKEYLESS_URL=' "$DOCKER_COMPOSE_FILE" | head -n1 | sed 's/.*AKEYLESS_URL=//' | tr -d "'" | tr -d '"' | tr -d ' ')
        
        # Set default value for AKEYLESS_URL if not found
        AKEYLESS_URL=${AKEYLESS_URL:-"https://vault.akeyless.io"}

        # Read CA_PUB from the correct file if it exists
        if [ -f "$BASE_DIR/creds/ca.pub" ]; then
            CA_PUB=$(cat "$BASE_DIR/creds/ca.pub")
        else
            CA_PUB=""
        fi

        # Create a backup of the existing docker-compose file
        create_backup
    else
        echo "No existing docker-compose file found. Using empty defaults."
        ADMIN_ACCESS_ID=""
        ADMIN_ACCESS_KEY=""
        BASTION_ACCESS_ID=""
        BASTION_ACCESS_KEY=""
        SSO_ACCESS_ID=""
        CA_PUB=""
        AKEYLESS_URL="https://vault.akeyless.io"
    fi
}

# Function to get Docker credentials from Akeyless
get_docker_creds() {
    local uid_token

    echo "Your Akeyless Customer Success representative can access this "
    echo "from the Akeyless internal portal from this path : "
    echo "UID Auth Method: '/customer-success/docker-creds/cs-poc-uid-docker-creds'"
    echo

    # Check if UID_TOKEN is set as an environment variable
    if [ -z "$UID_TOKEN" ]; then
        read -p "Enter your Akeyless UID token: " uid_token
    else
        uid_token="$UID_TOKEN"
    fi

    # Make the API call to Akeyless
    local api_response
    api_response=$(curl -s --request POST \
         --url https://api.akeyless.io/get-secret-value \
         --header 'accept: application/json' \
         --header 'content-type: application/json' \
         --data "{
      \"accessibility\": \"regular\",
      \"ignore-cache\": \"false\",
      \"json\": false,
      \"names\": [
        \"/docker-hub/users/customers/poc-token\"
      ],
      \"uid-token\": \"$uid_token\"
    }")

    # Extract Docker credentials
    local docker_creds
    docker_creds=$(echo "$api_response" | sed 's/.*"\/docker-hub\/users\/customers\/poc-token": "\(.*\)".*/\1/' | sed 's/\\n/\n/g' | sed -n '/^docker:/,/^$/p' | sed 's/^docker://' | tr -d '\n' | sed 's/^ *//;s/ *$//')

    if [ -z "$docker_creds" ]; then
        echo "Failed to retrieve Docker credentials. Please check your UID token and try again."
        exit 1
    fi

    # Split Docker credentials into username and password
    DOCKER_USERNAME=$(echo "$docker_creds" | cut -d':' -f1 | sed 's/^ *//;s/ *$//')
    DOCKER_PASSWORD=$(echo "$docker_creds" | cut -d':' -f2 | sed 's/^ *//;s/ *$//')

    if [ -z "$DOCKER_USERNAME" ] || [ -z "$DOCKER_PASSWORD" ]; then
        echo "Failed to parse Docker credentials. Please check the secret format in Akeyless."
        exit 1
    fi

    echo "Docker credentials retrieved successfully."
}

# Call the function to read existing values
read_existing_values

# Input Variables section with defaults from existing values
read -p "Enter the access ID to be used for GW authentication [$ADMIN_ACCESS_ID]: " admin_access_id_input
ADMIN_ACCESS_ID=${admin_access_id_input:-$ADMIN_ACCESS_ID}

read -p "Enter the access key to be used for authentication (leave blank if not needed) [$ADMIN_ACCESS_KEY]: " admin_access_key_input
ADMIN_ACCESS_KEY=${admin_access_key_input:-$ADMIN_ACCESS_KEY}

read -p "Enter the access ID for the SRA bastion [$BASTION_ACCESS_ID]: " bastion_access_id_input
BASTION_ACCESS_ID=${bastion_access_id_input:-$BASTION_ACCESS_ID}

read -p "Enter the Access Key for the SRA bastion (leave blank if not needed) [$BASTION_ACCESS_KEY]: " bastion_access_key_input
BASTION_ACCESS_KEY=${bastion_access_key_input:-$BASTION_ACCESS_KEY}

read -p "Enter the access ID for the Single Sign On (SAML/OIDC) [$SSO_ACCESS_ID]: " sso_access_id_input
SSO_ACCESS_ID=${sso_access_id_input:-$SSO_ACCESS_ID}

read -p "Enter the public key of the encryption key to be used for SSH Cert Issuer [$CA_PUB]: " ca_pub_input
CA_PUB=${ca_pub_input:-$CA_PUB}

read -p "Enter the Tenant information for the desired foundation [$AKEYLESS_URL]: " akeyless_url_input
AKEYLESS_URL=${akeyless_url_input:-$AKEYLESS_URL}

# Set up ADMIN_ACCESS_KEY_LINE
if [ "$ADMIN_ACCESS_KEY" == "" ]; then
    FULL_ADMIN_ACCESS_KEY_LINE="#- ADMIN_ACCESS_KEY="
else
    FULL_ADMIN_ACCESS_KEY_LINE="- ADMIN_ACCESS_KEY=$ADMIN_ACCESS_KEY"
fi

# Set up BASTION_ACCESS_KEY_LINE
if [ "$BASTION_ACCESS_KEY" == "" ]; then
    FULL_BASTION_ACCESS_KEY_LINE="#- PRIVILEGED_ACCESS_KEY="
else
    FULL_BASTION_ACCESS_KEY_LINE="- PRIVILEGED_ACCESS_KEY=$BASTION_ACCESS_KEY"
fi

# Check for proxy variables
PROXY_ENV=""
if [ ! -z "$http_proxy" ]; then
    PROXY_ENV="${PROXY_ENV}      - http_proxy=$http_proxy\n"
fi
if [ ! -z "$https_proxy" ]; then
    PROXY_ENV="${PROXY_ENV}      - https_proxy=$https_proxy\n"
fi
if [ ! -z "$no_proxy" ]; then
    PROXY_ENV="${PROXY_ENV}      - no_proxy=$no_proxy\n"
fi

# Get Docker credentials
get_docker_creds

# Perform Docker login
echo "Logging into Docker Hub..."
echo "$DOCKER_PASSWORD" | docker login -u "$DOCKER_USERNAME" --password-stdin

if [ $? -ne 0 ]; then
    echo "Docker login failed. Please check your credentials and try again."
    exit 1
fi

# Pull required images
echo "Pulling required Docker images..."
docker pull akeyless/zero-trust-bastion:latest
docker pull akeyless/zero-trust-web-dispatcher:latest
docker pull akeyless/zero-trust-web-worker:latest

# Check if all images were pulled successfully
if [ $? -ne 0 ]; then
    echo "Failed to pull one or more Docker images. Please check your internet connection and Docker Hub access."
    exit 1
fi

echo "All required images pulled successfully."

if [ ! -d $BASE_DIR/etc-ssh ] || [ ! -e $BASE_DIR/etc-ssh/ssh/sshd_config ]; then
    sudo rm -rf $BASE_DIR/etc-ssh
    mkdir -p $BASE_DIR/etc-ssh
    DOCKER_NAME="temp-ssh-container"
    IMAGE_NAME="akeyless/zero-trust-bastion:latest"
    docker run --name $DOCKER_NAME -d -p 0.0.0.0:2222:22 -p 0.0.0.0:9900:9900 $IMAGE_NAME
    echo "Waiting for ssh service to complete initial start..."
    for i in `seq 10 -1 1` ; do echo -e "$i " ; sleep 1 ; done
    docker cp $DOCKER_NAME:/etc/ssh $BASE_DIR/etc-ssh
    docker rm -f $DOCKER_NAME
fi

# Create necessary directories and files
mkdir -p $BASE_DIR/creds
mkdir -p $BASE_DIR/shared
mkdir -p $BASE_DIR/data/nginx/custom
mkdir -p $BASE_DIR/letsencrypt
mkdir -p $BASE_DIR/metrics

# Create the custom http.conf file
cat << EOF >| $BASE_DIR/data/nginx/custom/http.conf
# SSL redirect (uncomment if you have SSL configured in NPM)
# ssl_redirect on;

# Timeouts
proxy_connect_timeout 3600s;
proxy_read_timeout 3600s;
proxy_send_timeout 3600s;

# Buffer settings
proxy_buffer_size 8k;
proxy_buffers 4 8k;

# Sticky session configuration
proxy_cookie_path / "/; HttpOnly; Secure; SameSite=strict";
proxy_cookie_flags ~ secure httponly samesite=strict;

map \$cookie_sessionid \$sticky_session {
    default   0;
    ~.+       1;
}
EOF

echo 'http://agw:8080' > $BASE_DIR/creds/akeyless_config_file
if [ "$BASTION_ACCESS_KEY" == "" ]; then
    echo "cmd=auth&access-id=$BASTION_ACCESS_ID" >> $BASE_DIR/creds/akeyless_config_file
else
    echo "cmd=auth&access-id=$BASTION_ACCESS_ID&access-key=$BASTION_ACCESS_KEY" >> $BASE_DIR/creds/akeyless_config_file
fi
echo "$CA_PUB" > $BASE_DIR/creds/ca.pub

# Create log forwarding configuration
cat << EOF >| $BASE_DIR/log_forwarding.conf
target_syslog_tag="ssh-audit-export"
target_log_type="syslog"
target_syslog_network="udp"
target_syslog_host="syslog:514"
EOF

# Generate policies.json file
cat << EOF >| $BASE_DIR/policies.json
{
  "policies": {
    "BlockAboutConfig": true,
    "BlockAboutAddons": true,
    "BlockAboutProfiles": true,
    "BlockAboutSupport": true,
    "DisableDeveloperTools": true,
    "DisableFirefoxAccounts": true,
    "DisablePasswordReveal": true,
    "DisablePrivateBrowsing": true,
    "DisableProfileImport": true,
    "DisableSafeMode": true,
    "OfferToSaveLogins": false,
    "OfferToSaveLoginsDefault": false,
    "PasswordManagerEnabled": false,
    "Proxy": {
      "Mode": "none",
      "Locked": true
    },
    "Preferences": {
      "layout.forms.reveal-password-context-menu.enabled": {
        "Value": false,
        "Status": "locked"
      }
    },
    "WebsiteFilter": {
      "Block": [
        "<all_urls>"
      ],
      "Exceptions": [
        "https://*.akeyless.io/*",
        "https://*.akeyless-security.com/*",
        "https://*.gitlab.com/*",
        "https://*.slack.com/*",
        "https://*.amazon.com/*",
        "https://*.microsoftonline.com/*",
        "https://*.azure.com/*"
      ]
    }
  }
}
EOF





# Generate the docker-compose.yml file
cat << EOF >| $DOCKER_COMPOSE_FILE
version: '3.9'
services:
  agw:
    environment:
      - ALLOWED_ACCESS_IDS=$SSO_ACCESS_ID,$BASTION_ACCESS_ID
      - CLUSTER_NAME=sraDockerCompose
      - ADMIN_ACCESS_ID=$ADMIN_ACCESS_ID
      $FULL_ADMIN_ACCESS_KEY_LINE
      - AKEYLESS_URL=$AKEYLESS_URL
      #- VERSION=4.15.0
$(echo -e "$PROXY_ENV")
    ports:
      - '8000:8000'
      - '8200:8200'
      - '18888:18888'
      - '8080:8080'
      - '8081:8081'
    container_name: agw
    restart: unless-stopped
    image: akeyless/base:latest
    privileged: true
    networks:
      vpcbr:
        ipv4_address: 10.5.0.5

  ssh:
    environment:
      - DEBUG=1
      - CLUSTER_NAME=docker-compose-sra
      - ALLOWED_ACCESS_IDS=$SSO_ACCESS_ID,$BASTION_ACCESS_ID
      - BASTION_TYPE=ssh-proxy
      - AKEYLESS_GW_URL=http://agw:8080
      - AKEYLESS_URL=$AKEYLESS_URL
$(echo -e "$PROXY_ENV")
    cap_add:
      - SYS_ADMIN
    ports:
      - '2222:22'
      - '9900:9900'
    volumes:
      - $PWD/creds/akeyless_config_file:/var/akeyless/conf/akeyless_config_file
      - $PWD/creds:/var/akeyless/creds
      - $PWD/etc-ssh/ssh:/etc/ssh
      - $PWD/log_forwarding.conf:/var/akeyless/conf/logand.conf
    container_name: ssh-bastion
    privileged: true
    restart: unless-stopped
    image: akeyless/zero-trust-bastion:latest
    networks:
      vpcbr:
        ipv4_address: 10.5.0.6

  syslog:
    environment:
      - FOO=bar1
$(echo -e "$PROXY_ENV")
    image: balabit/syslog-ng:latest
    hostname: syslog
    container_name: syslog
    restart: unless-stopped
    ports:
      - "514:514/udp"
      - "601:601"
      - "6514:6514"
    networks:
      vpcbr:
        ipv4_address: 10.5.0.7

  dispatcher:
    image: "akeyless/zero-trust-web-dispatcher:latest"
    container_name: web-dispatcher
    environment:
      - CLUSTER_NAME=docker-ztwa
      - SERVICE_DNS=worker
      - AKEYLESS_GW_URL=http://agw:8080
      - PRIVILEGED_ACCESS_ID=$BASTION_ACCESS_ID
      $FULL_BASTION_ACCESS_KEY_LINE
      - ALLOWED_ACCESS_IDS=$SSO_ACCESS_ID,$BASTION_ACCESS_ID
      - ALLOW_INTERNAL_AUTH=false
      - DISABLE_SECURE_COOKIE=true
      - WEB_PROXY_TYPE=http
      - WEB_WORKER_SERVICE_DNS=worker
      - AKEYLESS_URL=$AKEYLESS_URL
$(echo -e "$PROXY_ENV")
    ports:
      - "9000:9000"
      - "19414:19414"
      - "2000:2000"
    volumes:
      - $PWD/shared:/etc/shared
      - $PWD/creds/akeyless_config_file:/var/akeyless/conf/akeyless_config_file
    restart: unless-stopped
    networks:
      vpcbr:
        ipv4_address: 10.5.0.2

  worker:
    image: "akeyless/zero-trust-web-worker:latest"
    container_name: web-worker
    security_opt:
      - seccomp=unconfined
    shm_size: '2gb'
    volumes:
      - $PWD/policies.json:/usr/lib/firefox/distribution/policies.json:ro
      - $PWD/shared:/etc/shared
    environment:
      - INTERNAL_DISPATCHER_IP=10.5.0.2
      - DISPLAY_WIDTH=2560
      - DISPLAY_HEIGHT=1200
      - WEB_DISPATCHER_SERVICE_DNS=dispatcher
      - FF_PREF_HOMEPAGE=https://www.akeyless.io
      - AKEYLESS_URL=$AKEYLESS_URL
$(echo -e "$PROXY_ENV")
    healthcheck:
      test: curl -f http://localhost:9090/healthy
      interval: 1s
      retries: 3
      timeout: 3s
      start_period: 10s
    restart: unless-stopped
    networks:
      - vpcbr
    depends_on:
     - dispatcher

  anpm:
    environment:
      - DISABLE_IPV6=true
$(echo -e "$PROXY_ENV")
    image: 'jc21/nginx-proxy-manager:latest'
    restart: unless-stopped
    container_name: anpm
    ports:
      - '80:80'
      - '443:443'
      - '81:81'
    cap_add:
      - CAP_NET_BIND_SERVICE
    volumes:
      - $PWD/data:/data
      - $PWD/letsencrypt:/etc/letsencrypt
      - $PWD/data/nginx/custom:/etc/nginx/custom
    networks:
      vpcbr:
        ipv4_address: 10.5.0.8

  autoheal:
    restart: unless-stopped
    image: willfarrell/autoheal
    environment:
      - AUTOHEAL_CONTAINER_LABEL=all
$(echo -e "$PROXY_ENV")
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
    networks:
      - vpcbr

networks:
  vpcbr:
    driver: bridge
    ipam:
     config:
       - subnet: 10.5.0.0/24
         gateway: 10.5.0.1

EOF


# Generate the help.sh script
cat << EOF >| $BASE_DIR/help.sh
#!/usr/bin/env bash

echo "Command to start docker-compose:"
echo "docker compose up -d"
echo -e "\nCommand to view Gateway logs:\ndocker logs -f agw"
echo -e "\nCommand to view SSH bastion logs:\ndocker logs -f ssh-bastion"
echo -e "\nCommand to view SSH transcripts:\ndocker exec -it syslog tail -f /var/log/messages"
echo -e "\nCommand to connect to this host through the bastion:"
echo "akeyless connect -t \$(whoami)@\$(curl -s icanhazip.com || echo 'YOUR_PUBLIC_IP'):22 -v localhost:2222 -c \"/MySSHCert2\""
EOF

# Make the help.sh script executable
chmod +x $BASE_DIR/help.sh

# Execute the help.sh script
$BASE_DIR/help.sh