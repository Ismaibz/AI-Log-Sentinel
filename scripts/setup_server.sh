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
    read -rp "$prompt: " answer < /dev/tty
    echo "${answer:-$default}"
}

ask_yes() {
    local prompt="$1"
    local default="${2:-n}"
    local answer
    read -rp "$prompt [$default]: " answer < /dev/tty
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

get_server_names() {
    local conf="$1"
    grep -oP 'server_name\s+\K[^;]+' "$conf" 2>/dev/null || true
}

get_access_log() {
    local conf="$1"
    grep -oP 'access_log\s+\K[^;]+' "$conf" 2>/dev/null | head -1 || true
}

configure_site() {
    local conf="$1"
    local base
    base=$(basename "$conf" .conf)

    local server_names
    server_names=$(get_server_names "$conf")
    [[ -n "$server_names" ]] || return 1

    local primary_name
    primary_name=$(echo "$server_names" | awk '{print $1}')

    echo ""
    echo -e "${BOLD}--- Site: ${CYAN}$primary_name${NC} (${conf}) ---"

    if grep -q "sentinel.d" "$conf" 2>/dev/null; then
        ok "Already includes sentinel.d — skipping"
        return 1
    fi

    if ! ask_yes "Configure Sentinel for $primary_name?" "y"; then
        return 1
    fi

    local access_log
    access_log=$(get_access_log "$conf")

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
    else
        ok "access_log: $access_log"
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

    echo "${source_name}|${access_log}"
}

step_install_sentinel_config() {
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

    local sources_block=""
    for src in "${sources[@]}"; do
        local src_name="${src%%|*}"
        local src_log="${src#*|}"
        sources_block+="[[pipeline.log_sources]]
name = \"${src_name}\"
path = \"${src_log}\"
format = \"nginx\"
enabled = true

"
    done

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

${sources_block}[reasoning]
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

step_install_sudoers() {
    local sudoers_src="${SENTINEL_APP_DIR}/scripts/sentinel-sudoers"
    if [[ ! -f "$sudoers_src" ]]; then
        warn "sudoers file not found at $sudoers_src"
        return
    fi

    local target="/etc/sudoers.d/sentinel"
    cp "$sudoers_src" "$target"
    chmod 440 "$target"
    if visudo -c -f "$target" >/dev/null 2>&1; then
        ok "Sudoers installed at $target (sentinel can run nginx/ufw commands)"
    else
        error "Sudoers syntax error — removing $target"
        rm -f "$target"
        return 1
    fi
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

    info "Step 4/8: Configure sites"
    local sentinel_sources=()
    for conf in "$NGINX_CONF_DIR"/*.conf; do
        [[ -f "$conf" ]] || continue
        local result
        if result=$(configure_site "$conf"); then
            sentinel_sources+=("$result")
        fi
    done

    if [[ ${#sentinel_sources[@]} -eq 0 ]]; then
        warn "No sites configured. Exiting."
        exit 0
    fi

    info "Step 5/8: Generate Sentinel config"
    step_install_sentinel_config "${sentinel_sources[@]}"

    info "Step 6/8: Set permissions & sudoers"
    step_set_permissions
    step_install_sudoers

    info "Step 7/8: Test nginx, reload & install service"
    step_nginx_test
    step_reload_nginx
    step_install_service

    echo ""
    echo -e "${GREEN}${BOLD}Setup complete!${NC}"
    echo ""
    info "Sources configured:"
    for src in "${sentinel_sources[@]}"; do
        echo "  - ${src%%|*} → ${src#*|}"
    done
    echo ""
    info "Next steps:"
    echo "  1. Edit ${SENTINEL_CONFIG} — set Telegram chat_id + bot token"
    echo "  2. Configure secrets.vibe with your Gemini API key"
    echo "  3. Set dry_run = false when ready for real mitigation"
    echo "  4. Watch: journalctl -u ai-log-sentinel -f"
}

main "$@"
