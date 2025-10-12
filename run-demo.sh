#!/bin/bash
# This script automates the setup of a local development environment.

set -e

cleanup() {
    echo ""
    echo "--- Shutting down server ---"
    # The PID is stored in a variable. Kill the process.
    if [ -n "$SERVER_PID" ]; then
        kill $SERVER_PID 2>/dev/null || true
    fi
}
trap cleanup EXIT

echo "--> Creating .env file"
cat > .env << EOF
LISTEN_PORT=8080
TARGET_URL=http://localhost:8081
SESSION_SECRET=$(openssl rand -base64 32)
CSRF_SECRET_KEY=$(openssl rand -base64 32)
DATABASE_PATH=./auth.db
PROTECT_API=true
PROTECT_FRONTEND=true
MAX_LOGIN_ATTEMPTS=5
LOCKOUT_DURATION_MINUTES=10
EOF

echo "--> Building application"
go build -o auth-proxy-server ./cmd/server
go build -o admin-cli ./cmd/admin-cli

rm -f ./auth.db

echo "--> Starting server in background"
./auth-proxy-server &
SERVER_PID=$!

sleep 3

echo "--> Creating admin user"
./admin-cli --username "admin" --password "password123"

echo "--> Fetching API token"
JSON_DATA='{"username": "admin", "password": "password123"}'
TOKEN_RESPONSE=$(curl -s -X POST -H "Content-Type: application/json" -d "$JSON_DATA" http://localhost:8080/api/auth/token)

echo ""
echo "==================================="
echo "Dev Server is Ready"
echo ""
echo "Server is running (PID: $SERVER_PID)"
echo "Admin user: admin / password123"
echo ""
echo "API Token Response:"
echo "$TOKEN_RESPONSE"
echo "==================================="
echo "Proxy is listening on http://localhost:8080/login"
echo "Backend target is http://localhost:8081"
echo ""
echo "Press Ctrl+C to stop the server."

wait $SERVER_PID
