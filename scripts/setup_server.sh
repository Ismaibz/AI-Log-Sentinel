#!/usr/bin/env bash
set -euo pipefail

NGINX_CONF="/etc/nginx/nginx.conf"
NGINX_CONF_DIR="/etc/nginx/conf.d"
SENTINEL_DIR="/etc/nginx/sentinel.d"
SENTINEL_CONFIG="/etc/sentinel/config.toml"
SENTINEL_APP_DIR="/opt/ai-log-sentinel"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

info()  { echo -e "${CYAN}[INFO]${NC} $*"; }
ok()    { echo -e "${GREEN}[OK]${NC} $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*"; }

ask() {
    local prompt="$1"
    local default="${2:-}"
    local answer
    if [[ -n "$default" ]]; then
        prompt="$prompt [$default]"
    fi
    read -rp "$prompt: " answer
    echo "${answer:-$default}"
}

ask_yes() {
    local prompt="$1"
    local default="${2:-n}"
    local answer
    read -rp "$prompt [$default]: " answer
    answer="${answer:-$default}"
    [[ "$answer" =~ ^[Yy] ]]
}

require_root() {
    if [[ $EUID -ne 0 ]]; then
        error "Run as root: sudo bash $0"
        exit 1
    fi
}

backup_file() {
    local file="$1"
    local backup="${file}.bak.$(date +%Y%m%d%H%M%S)"
    cp "$file" "$backup"
    ok "Backup: $backup"
}

step_create_user() {
    if id "sentinel" &>/dev/null; then
        ok "User 'sentinel' already exists"
    else
        useradd -r -s /bin/false sentinel
        ok "Created system user 'sentinel'"
    fi
}

step_create_sentinel_dir() {
    mkdir -p "$SENTINEL_DIR"
    ok "Created $SENTINEL_DIR"
}

step_patch_nginx_conf() {
    if grep -q "sentinel.d" "$NGINX_CONF" 2>/dev/null; then
        ok "nginx.conf already includes sentinel.d"
        return
    fi

    info "Patching $NGINX_CONF to include sentinel.d"

    backup_file "$NGINX_CONF"

    if grep -q "include.*conf.d" "$NGINX_CONF"; then
        sed -i "/include.*conf.d/i\\    include ${SENTINEL_DIR}/*.conf;" "$NGINX_CONF"
    else
        error "Cannot find 'include conf.d' line in $NGINX_CONF"
        error "Add this line manually inside the http {} block:"
        error "    include ${SENTINEL_DIR}/*.conf;"
        return 1
    fi

    ok "Added sentinel.d include to nginx.conf"
}

step_detect_sites() {
    local tmpfile="$1"
    > "$tmpfile"

    for conf in "$NGINX_CONF_DIR"/*.conf; do
        [[ -f "$conf" ]] || continue
        local server_names
        server_names=$(grep -oP 'server_name\s+\K[^;]+' "$conf" 2>/dev/null || true)
        [[ -n "$server_names" ]] || continue

        local base
        base=$(basename "$conf" .conf)
        printf '%s\t%s\t%s\n' "$base" "$server_names" "$conf" >> "$tmpfile"
    done

    [[ -s "$tmpfile" ]]
}

step_configure_site() {
    local base="$1"
    local server_names="$2"
    local conf="$3"
    local out_name="$4"
    local out_log="$5"
    local primary_name
    primary_name=$(echo "$server_names" | awk '{print $1}')

    echo ""
    echo -e "${BOLD}--- Site: ${CYAN}$primary_name${NC} (${conf}) ---"

    if grep -q "sentinel.d" "$conf" 2>/dev/null; then
        ok "Already includes sentinel.d — skipping"
        return 0
    fi

    if ! ask_yes "Configure Sentinel for $primary_name?" "y"; then
        return 0
    fi

    local access_log
    access_log=$(grep -oP 'access_log\s+\K[^;]+' "$conf" 2>/dev/null | head -1 || true)

    if [[ -z "$access_log" ]]; then
        access_log="/var/log/nginx/${base}_access.log"
        warn "No access_log found in $conf"
        if ask_yes "Add access_log $access_log?" "y"; then
            backup_file "$conf"
            sed -i "/server_name.*;/a\\    access_log ${access_log};" "$conf"
            ok "Added access_log to $conf"
        else
            access_log=$(ask "Enter access_log path" "/var/log/nginx/${base}_access.log")
        fi
    fi

    local sentinel_include="include ${SENTINEL_DIR}/*.conf;"
    if ! grep -q "$sentinel_include" "$conf" 2>/dev/null; then
        if grep -q "access_log" "$conf"; then
            sed -i "/access_log.*;/a\\    ${sentinel_include}" "$conf"
        else
            sed -i "/server_name.*;/a\\    ${sentinel_include}" "$conf"
        fi
        ok "Added sentinel include to $conf"
    fi

    local source_name
    source_name=$(ask "Source name for config.toml" "$base-nginx")

    printf -v "$out_name" '%s' "$source_name"
    printf -v "$out_log" '%s' "$access_log"
}

step_install_sentinel_config() {
    shift
    local sources=("$@")

    if [[ -f "$SENTINEL_CONFIG" ]]; then
        ok "Config exists at $SENTINEL_CONFIG"
        if ! ask_yes "Overwrite?" "n"; then
            info "Skipping config generation. Add the sources manually."
            return
        fi
        backup_file "$SENTINEL_CONFIG"
    fi

    mkdir -p "$(dirname "$SENTINEL_CONFIG")"

    local api_key
    api_key=$(ask "Gemini API key (or leave empty to set later)" "")

    cat > "$SENTINEL_CONFIG" <<EOF
[general]
app_name = "AI-Log-Sentinel"
log_level = "INFO"

[secrets]
vault_path = "${SENTINEL_APP_DIR}/secrets.vibe"
project_id = "AI-Log-Sentinel"
file_key = true

[alerting]
channels = ["telegram"]
min_severity = "medium"

[alerting.telegram]
chat_id = ""
bot_token_secret = "TELEGRAM_BOT_TOKEN"

[pipeline]
batch_size = 5
batch_interval = 10
max_queue_size = 1000

$(for src in "${sources[@]}"; do
    local src_name src_log
    src_name="${src%%|*}"
    src_log="${src#*|}"
    cat <<TOML
[[pipeline.log_sources]]
name = "${src_name}"
path = "${src_log}"
format = "nginx"
enabled = true

TOML
done)
[reasoning]
provider = "gemini"

[reasoning.gemini]
api_key = "${api_key}"

[reasoning.l2_deep]
enabled = true

[anonymization]
enabled = true

[mitigation]
enabled = true
dry_run = true
auto_approve_severity = []
data_dir = "${SENTINEL_APP_DIR}/data"

[mitigation.hitl]
timeout = 300

[mitigation.executor]
nginx_config_dir = "${SENTINEL_DIR}"
nginx_reload_cmd = "sudo nginx -s reload"
ufw_cmd = "sudo ufw"
rollback_on_failure = true
EOF

    ok "Config written to $SENTINEL_CONFIG"
}

step_nginx_test() {
    info "Testing nginx configuration..."
    if nginx -t 2>&1; then
        ok "Nginx config is valid"
    else
        error "Nginx config test failed — check the errors above"
        error "Backups are in place with .bak.* extension"
        return 1
    fi
}

step_set_permissions() {
    mkdir -p "${SENTINEL_APP_DIR}/data" "${SENTINEL_APP_DIR}/.offsets"
    chown -R sentinel:sentinel "${SENTINEL_APP_DIR}/data" "${SENTINEL_APP_DIR}/.offsets"
    chown sentinel:sentinel "$SENTINEL_DIR"
    chmod 755 "$SENTINEL_DIR"
    ok "Permissions set for sentinel user"
}

step_reload_nginx() {
    if ask_yes "Reload nginx now?" "y"; then
        nginx -s reload
        ok "Nginx reloaded"
    fi
}

step_install_service() {
    local service_src="${SENTINEL_APP_DIR}/scripts/ai-log-sentinel.service"
    if [[ -f "$service_src" ]]; then
        cp "$service_src" /etc/systemd/system/
        systemctl daemon-reload
        ok "Service installed"
        if ask_yes "Enable and start service now?" "y"; then
            systemctl enable --now ai-log-sentinel
            ok "Service started"
            echo ""
            info "Watch logs: journalctl -u ai-log-sentinel -f"
        fi
    else
        warn "Service file not found at $service_src"
        warn "Install manually: cp scripts/ai-log-sentinel.service /etc/systemd/system/"
    fi
}

main() {
    echo -e "${BOLD}"
    echo "╔══════════════════════════════════════════╗"
    echo "║   AI-Log-Sentinel — Server Setup         ║"
    echo "╚══════════════════════════════════════════╝"
    echo -e "${NC}"

    require_root

    info "Step 1/8: Create system user"
    step_create_user

    info "Step 2/8: Create sentinel nginx directory"
    step_create_sentinel_dir

    info "Step 3/8: Patch nginx.conf"
    step_patch_nginx_conf

    info "Step 4/8: Detect sites in $NGINX_CONF_DIR"
    local sites_file
    sites_file=$(mktemp)
    if ! step_detect_sites "$sites_file"; then
        error "No sites found in $NGINX_CONF_DIR"
        rm -f "$sites_file"
        exit 1
    fi

    local sentinel_sources=()
    while IFS=$'\t' read -r base server_names conf; do
        local src_name="" src_log=""
        step_configure_site "$base" "$server_names" "$conf" src_name src_log
        if [[ -n "$src_name" ]]; then
            sentinel_sources+=("${src_name}|${src_log}")
        fi
    done < "$sites_file"
    rm -f "$sites_file"

    if [[ ${#sentinel_sources[@]} -eq 0 ]]; then
        warn "No sites configured. Exiting."
        exit 0
    fi

    info "Step 5/8: Generate Sentinel config"
    step_install_sentinel_config "skip" "${sentinel_sources[@]}"

    info "Step 6/8: Test nginx config"
    step_nginx_test

    info "Step 7/8: Set permissions"
    step_set_permissions

    info "Step 8/8: Reload nginx & install service"
    step_reload_nginx
    step_install_service

    echo ""
    echo -e "${GREEN}${BOLD}Setup complete!${NC}"
    echo ""
    info "Sources configured:"
    for src in "${sentinel_sources[@]}"; do
        local s_name s_log
        s_name="${src%%|*}"
        s_log="${src#*|}"
        echo "  - $s_name → $s_log"
    done
    echo ""
    info "Next steps:"
    echo "  1. Edit ${SENTINEL_CONFIG} — set Telegram chat_id + bot token"
    echo "  2. Configure secrets.vibe with your Gemini API key"
    echo "  3. Set dry_run = false when ready for real mitigation"
    echo "  4. Watch: journalctl -u ai-log-sentinel -f"
}

main "$@"
