#!/bin/bash
# Run on Linode as root after pushing IAM to Jenkins or building locally
set -euo pipefail

echo "=== Creating IAM database ==="
sudo -u postgres psql <<'SQL'
DO $$ BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'iam') THEN
    CREATE ROLE iam WITH LOGIN PASSWORD 'iam';
  END IF;
END $$;
SELECT 'CREATE DATABASE iam OWNER iam'
WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'iam')\gexec
GRANT ALL PRIVILEGES ON DATABASE iam TO iam;
SQL

sudo -u postgres psql -d iam -c "GRANT ALL ON SCHEMA public TO iam;"

echo "=== Installing byz-iam CLI ==="
install -m 755 "$(dirname "$0")/byz-iam" /usr/local/bin/byz-iam

echo "=== Supervisor config ==="
cat > /etc/supervisor/conf.d/iam.conf <<'EOF'
[program:iam]
directory=/opt/services/iam
command=/bin/bash -c 'test -f /opt/services/iam/app.jar && exec /usr/lib/jvm/temurin-23-jdk-amd64/bin/java -jar -Xmx512M /opt/services/iam/app.jar --server.port=8082 || (echo "app.jar not deployed yet" && sleep 3600)'
user=root
autostart=true
autorestart=true
startsecs=15
environment=JAVA_HOME="/usr/lib/jvm/temurin-23-jdk-amd64",DB_URL="jdbc:postgresql://127.0.0.1:5432/iam",DB_USER="iam",DB_PASS="iam",IAM_ISSUER="https://iam.byzantineapp.dev",IAM_KEY_DIR="/opt/services/iam/keys"
stdout_logfile=/var/log/supervisor/iam.log
stderr_logfile=/var/log/supervisor/iam.err.log
EOF

echo "=== Nginx site ==="
cat > /etc/nginx/sites-available/iam.byzantineapp.dev <<'EOF'
server {
    listen 80;
    listen [::]:80;
    server_name iam.byzantineapp.dev;

    location / {
        proxy_pass http://127.0.0.1:8082;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
EOF
ln -sf /etc/nginx/sites-available/iam.byzantineapp.dev /etc/nginx/sites-enabled/
nginx -t && systemctl reload nginx

echo "=== SSL (after DNS A record for iam -> server IP) ==="
echo "Run: certbot --nginx -d iam.byzantineapp.dev --non-interactive --agree-tos --register-unsafely-without-email --redirect"

mkdir -p /opt/services/iam/keys
supervisorctl reread
supervisorctl update iam || true

echo "Done. Next:"
echo "  1. Add DNS A record: iam.byzantineapp.dev"
echo "  2. Deploy app.jar to /opt/services/iam/"
echo "  3. byz-iam org-create \"BuilderBuddy\""
echo "  4. byz-iam tenant-create builderbuddy \"Default\""
echo "  5. byz-iam client-create builderbuddy builderbuddy-ios \"BuilderBuddy iOS\" public"