#!/bin/bash

# Configuration
CERT_DIR="./certs"
CA_CN="Aegis-Root-CA"
AGENT_CN="aegis-agent"
CONTROLLER_CN="aegis-controller"
WEB_CN="localhost"

# Create certs directory
mkdir -p "$CERT_DIR"
cd "$CERT_DIR" || exit 1

echo "Generating Aegis Certificates in $CERT_DIR..."

# Generate root certificate authority (CA)
echo "-> Generating Root CA..."
openssl req -x509 -newkey rsa:4096 -days 3650 -nodes \
  -keyout ca.key -out ca.pem \
  -subj "/C=IN/ST=Karnataka/L=Bengaluru/O=Aegis/CN=$CA_CN"

# Generate agent gRPC server sertificates (mTLS)
echo "-> Generating Agent Server Certificates..."
openssl genrsa -out agent.key 2048

# Create a temporary OpenSSL config for the Agent SANs
cat > agent_ext.cnf <<EOF
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
extendedKeyUsage = serverAuth, clientAuth
subjectAltName = @alt_names
[alt_names]
DNS.1 = $AGENT_CN
DNS.2 = gateway
IP.1 = 172.21.0.10
IP.2 = 127.0.0.1
EOF

openssl req -new -key agent.key -out agent.csr \
  -subj "/C=IN/ST=Karnataka/L=Bengaluru/O=Aegis/CN=$AGENT_CN"

openssl x509 -req -in agent.csr -CA ca.pem -CAkey ca.key -CAcreateserial \
  -out agent.pem -days 825 -sha256 -extfile agent_ext.cnf

# Generate controller gRPC client certificates (mTLS)
echo "-> Generating Controller mTLS Client Certificates..."
openssl genrsa -out controller.key 2048

cat > controller_ext.cnf <<EOF
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
extendedKeyUsage = clientAuth
subjectAltName = @alt_names
[alt_names]
DNS.1 = $CONTROLLER_CN
DNS.2 = controller
IP.1 = 127.0.0.1
EOF

openssl req -new -key controller.key -out controller.csr \
  -subj "/C=IN/ST=Karnataka/L=Bengaluru/O=Aegis/CN=$CONTROLLER_CN"

openssl x509 -req -in controller.csr -CA ca.pem -CAkey ca.key -CAcreateserial \
  -out controller.pem -days 825 -sha256 -extfile controller_ext.cnf

# Generate controller HTTPS web certificates
echo "-> Generating Controller Web HTTPS Certificates..."
openssl genrsa -out server.key 2048

cat > web_ext.cnf <<EOF
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names
[alt_names]
DNS.1 = localhost
DNS.2 = controller
IP.1 = 127.0.0.1
IP.2 = 172.21.0.10
EOF

openssl req -new -key server.key -out server.csr \
  -subj "/C=IN/ST=Karnataka/L=Bengaluru/O=Aegis/CN=$WEB_CN"

openssl x509 -req -in server.csr -CA ca.pem -CAkey ca.key -CAcreateserial \
  -out server.crt -days 825 -sha256 -extfile web_ext.cnf

# Clean up
rm *.csr *_ext.cnf ca.srl

echo "All certificates generated successfully in $CERT_DIR!"
ls -la
