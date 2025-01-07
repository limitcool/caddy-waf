#!/bin/bash
set -e

GREEN="\033[1;32m"
RED="\033[1;31m"
NC="\033[0m" # No Color

# Helper function to print success or error messages
print_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

print_error() {
    echo -e "${RED}❌ $1${NC}"
    exit 1
}

# Install Go if not present or if the version is outdated
if ! command -v go &> /dev/null || [[ $(go version | grep -oP '\d+\.\d+\.\d+') != "1.23.4" ]]; then
    echo -e "⚙️  Go not found or outdated. Installing Go 1.23.4..."
    wget https://go.dev/dl/go1.23.4.linux-amd64.tar.gz && \
    sudo rm -rf /usr/local/go && \
    sudo tar -C /usr/local -xzf go1.23.4.linux-amd64.tar.gz && \
    rm go1.23.4.linux-amd64.tar.gz && \
    export PATH=$PATH:/usr/local/go/bin && \
    print_success "Go 1.23.4 installed successfully." || print_error "Failed to install Go."
else
    print_success "Go 1.23.4 is already installed."
fi

# Install xcaddy if not present
if ! command -v xcaddy &> /dev/null; then
    echo -e "⚙️  xcaddy not found. Installing xcaddy..."
    go install github.com/caddyserver/xcaddy/cmd/xcaddy@latest && \
    export PATH=$PATH:$(go env GOPATH)/bin && \
    print_success "xcaddy installed successfully." || print_error "Failed to install xcaddy."
else
    print_success "xcaddy is already installed."
fi

# Clone the repository
if [ -d "caddy-waf" ]; then
    echo -e "🔄 caddy-waf directory already exists. Pulling latest changes..."
    cd caddy-waf && git pull || print_error "Failed to pull caddy-waf updates."
else
    echo -e "📥 Cloning caddy-waf repository..."
    git clone https://github.com/fabriziosalmi/caddy-waf.git && \
    cd caddy-waf && \
    print_success "caddy-waf repository cloned successfully." || print_error "Failed to clone repository."
fi

# Clean and update dependencies
echo -e "📦 Running go mod tidy..."
go mod tidy && print_success "Dependencies updated (go mod tidy)." || print_error "Failed to run go mod tidy."

echo -e "🔍 Fetching Go modules..."
go get -v github.com/fabriziosalmi/caddy-waf github.com/caddyserver/caddy/v2 github.com/oschwald/maxminddb-golang && \
print_success "Go modules fetched successfully." || print_error "Failed to fetch Go modules."

# Download GeoLite2 Country database
if [ ! -f "GeoLite2-Country.mmdb" ]; then
    echo -e "🌍 Downloading GeoLite2 Country database..."
    wget https://git.io/GeoLite2-Country.mmdb && \
    print_success "GeoLite2 database downloaded." || print_error "Failed to download GeoLite2 database."
else
    print_success "GeoLite2 database already exists."
fi

# Build with xcaddy
echo -e "⚙️  Building Caddy with caddy-waf module..."
xcaddy build --with github.com/fabriziosalmi/caddy-waf=./ && \
print_success "Caddy built successfully." || print_error "Failed to build Caddy."

# Format Caddyfile
echo -e "🧹 Formatting Caddyfile..."
caddy fmt --overwrite && \
print_success "Caddyfile formatted." || print_error "Failed to format Caddyfile."

# Run Caddy
echo -e "🚀 Starting Caddy server..."
./caddy run && \
print_success "Caddy is running." || print_error "Failed to start Caddy."
