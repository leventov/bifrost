#!/bin/sh
set -e

# Function to fix permissions on mounted volumes
fix_permissions() {
    # Check if /app/data exists and fix ownership if needed
    if [ -d "/app/data" ]; then
        # Get current user info
        CURRENT_UID=$(id -u)
        CURRENT_GID=$(id -g)
        
        # Get directory ownership
        DATA_UID=$(stat -c %u /app/data 2>/dev/null || echo "0")
        DATA_GID=$(stat -c %g /app/data 2>/dev/null || echo "0")
        
        # If ownership doesn't match current user, try to fix it
        if [ "$DATA_UID" != "$CURRENT_UID" ] || [ "$DATA_GID" != "$CURRENT_GID" ]; then
            echo "Fixing permissions on /app/data (was $DATA_UID:$DATA_GID, setting to $CURRENT_UID:$CURRENT_GID)"
            
            # Try to change ownership (will work if running as root or if user has permission)
            if chown -R "$CURRENT_UID:$CURRENT_GID" /app/data 2>/dev/null; then
                echo "Successfully updated permissions on /app/data"
            else
                echo "Warning: Could not change ownership of /app/data. You may need to run:"
                echo "  docker run --user \$(id -u):\$(id -g) ..."
                echo "  or ensure the host directory is owned by UID:GID $CURRENT_UID:$CURRENT_GID"
            fi
        fi
        
        # Ensure logs subdirectory exists with correct permissions
        mkdir -p /app/data/logs
        chmod 755 /app/data/logs 2>/dev/null || true
    fi
}

# Fix permissions only if using a writable app dir (kept for compatibility; Postgres mode does not rely on local files)
fix_permissions || true

# Parse command line arguments and set environment variables
parse_args() {
    while [ $# -gt 0 ]; do
        case $1 in
            --port|-port)
                if [ -n "$2" ]; then
                    export APP_PORT="$2"
                    shift 2
                else
                    echo "Error: --port requires a value"
                    exit 1
                fi
                ;;
            --host|-host)
                if [ -n "$2" ]; then
                    export APP_HOST="$2"
                    shift 2
                else
                    echo "Error: --host requires a value"
                    exit 1
                fi
                ;;
            *)
                # Keep other arguments for the main application
                set -- "$@" "$1"
                shift
                ;;
        esac
    done
}

# Parse arguments if any are provided
if [ $# -gt 1 ]; then
    parse_args "$@"
fi

# If Postgres env vars are present, generate config.json for Postgres-backed stores
generate_config_if_needed() {
    if [ -n "$BIFROST_DB_HOST" ] && [ -n "$BIFROST_DB_USER" ] && [ -n "$BIFROST_DB_PASSWORD" ]; then
        mkdir -p "$APP_DIR"
        cat >"$APP_DIR/config.json" <<JSON
{
  "client": {
    "enable_governance": true,
    "enforce_governance_header": true,
    "allow_direct_keys": false
  },
  "config_store": {
    "enabled": true,
    "type": "postgres",
    "config": {
      "host": "${BIFROST_DB_HOST}",
      "port": "${BIFROST_DB_PORT:-5432}",
      "user": "${BIFROST_DB_USER}",
      "password": "${BIFROST_DB_PASSWORD}",
      "db_name": "${BIFROST_DB_NAME:-postgres}",
      "ssl_mode": "${BIFROST_DB_SSLMODE:-disable}"
    }
  },
  "logs_store": {
    "enabled": false
  }
}
JSON
    fi
}

generate_config_if_needed

# Build the command with environment variables and standard arguments
exec /app/main -app-dir "$APP_DIR" -port "$APP_PORT" -host "$APP_HOST" -log-level "$LOG_LEVEL" -log-style "$LOG_STYLE"