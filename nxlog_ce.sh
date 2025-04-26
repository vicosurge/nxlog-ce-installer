#!/bin/bash
# Enhanced NXLog CE installation/uninstallation script (vibe coded with Claude 3.7)
# Purpose: Create required folders, compile NXLog CE, or uninstall it
# Supports: Debian, Ubuntu, Alpine, Rocky Linux, CentOS

set -e  # Exit immediately if a command exits with non-zero status

# Default directories
NX_BASE="/usr/local"
NX_ETC="${NX_BASE}/etc"
NX_VAR="${NX_BASE}/var"
NX_BIN="${NX_BASE}/bin"
NX_CONF_FILE="nxlog.conf" 
NX_CONF_SRC="configuration/${NX_CONF_FILE}"
LOG_FILE="nxlog_script.log"
OPERATION="install"  # Default operation

# Function declarations
log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" | tee -a "${LOG_FILE}"
}

error_exit() {
    log "ERROR: $1"
    exit 1
}

cleanup() {
    if [ "${OPERATION}" = "install" ]; then
        log "Cleaning up temporary files..."
        if [ -d "${NX_FOLDER}" ]; then
            rm -rf "${NX_FOLDER}"
        fi
        log "Cleanup completed."
    fi
}

show_help() {
    echo "Usage: $0 [OPTIONS]"
    echo "Manage NXLog CE installation"
    echo ""
    echo "Operations:"
    echo "  -i, --install    Install NXLog CE (default)"
    echo "  -u, --uninstall  Uninstall NXLog CE"
    echo ""
    echo "Options:"
    echo "  -h, --help       Show this help message"
    echo "  -k, --keep-deps  Keep development dependencies after installation"
    echo "  -b, --base-dir   Set base installation directory (default: /usr/local)"
    echo "  -f, --force      Force operation without confirmation (for uninstall)"
    echo ""
    exit 0
}

install_deps() {
    log "Detecting distribution to install required dependencies..."
    
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        DISTRO_NAME=$ID
    else
        DISTRO_NAME=$(cat /etc/issue | awk '{print $1}')
    fi
    
    case "${DISTRO_NAME}" in
        debian|ubuntu)
            log "Detected Debian-based distribution."
            apt-get update || error_exit "Failed to update package lists"
            apt-get install -y build-essential libapr1-dev libpcre3-dev libssl-dev libexpat1-dev || \
                error_exit "Failed to install dependencies"
            REMOVE_CMD="apt-get remove -y build-essential libpcre3-dev libexpat1-dev"
            ;;
        alpine)
            log "Detected Alpine Linux."
            apk add --no-cache make g++ tar apr-dev openssl-dev pcre-dev libdbi-dev openssl expat-dev zlib-dev perl perl-dev file python3-dev autoconf automake libtool || \
                error_exit "Failed to install dependencies"
            REMOVE_CMD="apk del make g++ openssl-dev libdbi-dev expat-dev zlib-dev perl-dev"
            ;;
        rocky|centos|rhel|fedora)
            log "Detected RPM-based distribution."
            yum install -y gcc apr-devel pcre-devel openssl-devel expat-devel make automake libtool || \
                error_exit "Failed to install dependencies"
            REMOVE_CMD="yum remove -y gcc apr-devel pcre-devel openssl-devel expat-devel make automake libtool"
            ;;
        *)
            error_exit "Unsupported distribution: ${DISTRO_NAME}. Please install dependencies manually."
            ;;
    esac
}

remove_deps() {
    if [ -n "${REMOVE_CMD}" ] && [ "${KEEP_DEPS}" != "true" ]; then
        log "Removing build dependencies..."
        ${REMOVE_CMD} || log "Warning: Failed to remove some dependencies"
    fi
}

stop_nxlog() {
    log "Attempting to stop NXLog service..."
    
    # Try systemd first
    if command -v systemctl >/dev/null 2>&1; then
        if systemctl is-active --quiet nxlog; then
            log "Stopping NXLog via systemd..."
            systemctl stop nxlog || log "Warning: Failed to stop NXLog service via systemd"
        fi
    fi
    
    # Then try traditional service command
    if command -v service >/dev/null 2>&1; then
        log "Stopping NXLog via service command..."
        service nxlog stop 2>/dev/null || true
    fi
    
    # Finally try the direct binary if it exists
    if [ -x "${NX_BIN}/nxlog" ]; then
        log "Stopping NXLog via binary..."
        "${NX_BIN}/nxlog" -s 2>/dev/null || true
    fi
    
    # Check if process is still running by PID file
    if [ -f "${NX_VAR}/run/nxlog/nxlog.pid" ]; then
        PID=$(cat "${NX_VAR}/run/nxlog/nxlog.pid" 2>/dev/null) || true
        if [ -n "${PID}" ] && ps -p "${PID}" >/dev/null 2>&1; then
            log "Sending TERM signal to process ${PID}..."
            kill "${PID}" 2>/dev/null || true
            sleep 2
            
            # Force kill if still running
            if ps -p "${PID}" >/dev/null 2>&1; then
                log "Sending KILL signal to process ${PID}..."
                kill -9 "${PID}" 2>/dev/null || true
            fi
        fi
    fi
    
    log "NXLog should be stopped now."
}

uninstall_nxlog() {
    log "Starting NXLog uninstallation process..."
    
    # Stop any running instances
    stop_nxlog
    
    # Check if main binary exists to confirm installation
    if [ ! -x "${NX_BIN}/nxlog" ]; then
        if [ "${FORCE}" != "true" ]; then
            error_exit "NXLog binary not found at ${NX_BIN}/nxlog. Use --force to bypass this check."
        else
            log "Warning: NXLog binary not found but proceeding due to --force flag"
        fi
    fi
    
    # Confirmation unless forced
    if [ "${FORCE}" != "true" ]; then
        echo -n "Are you sure you want to uninstall NXLog? This will remove all configuration and data. [y/N]: "
        read -r CONFIRM
        if [ "${CONFIRM}" != "y" ] && [ "${CONFIRM}" != "Y" ]; then
            log "Uninstallation cancelled by user"
            exit 0
        fi
    fi
    
    log "Removing NXLog files and directories..."
    
    # Remove binaries
    if [ -x "${NX_BIN}/nxlog" ]; then
        rm -f "${NX_BIN}/nxlog" || log "Warning: Failed to remove ${NX_BIN}/nxlog"
    fi
    
    # Remove configuration directory
    if [ -d "${NX_ETC}/nxlog" ]; then
        if [ "${FORCE}" = "true" ]; then
            rm -rf "${NX_ETC}/nxlog" || log "Warning: Failed to remove ${NX_ETC}/nxlog"
        else
            # Backup configuration first
            BACKUP_DIR="${HOME}/nxlog_conf_backup_$(date +%Y%m%d%H%M%S)"
            log "Backing up configuration to ${BACKUP_DIR}..."
            mkdir -p "${BACKUP_DIR}" || log "Warning: Failed to create backup directory"
            cp -r "${NX_ETC}/nxlog" "${BACKUP_DIR}/" || log "Warning: Failed to backup configuration"
            
            rm -rf "${NX_ETC}/nxlog" || log "Warning: Failed to remove ${NX_ETC}/nxlog"
        fi
    fi
    
    # Remove run and spool directories
    rm -rf "${NX_VAR}/run/nxlog" || log "Warning: Failed to remove ${NX_VAR}/run/nxlog"
    rm -rf "${NX_VAR}/spool/nxlog" || log "Warning: Failed to remove ${NX_VAR}/spool/nxlog"
    
    # Remove lib directory if exists
    if [ -d "${NX_BASE}/lib/nxlog" ]; then
        rm -rf "${NX_BASE}/lib/nxlog" || log "Warning: Failed to remove ${NX_BASE}/lib/nxlog"
    fi
    
    # Remove systemd service if exists
    if [ -f "/etc/systemd/system/nxlog.service" ]; then
        rm -f "/etc/systemd/system/nxlog.service" || log "Warning: Failed to remove systemd service file"
        systemctl daemon-reload 2>/dev/null || true
    fi
    
    # Remove init.d script if exists
    if [ -f "/etc/init.d/nxlog" ]; then
        rm -f "/etc/init.d/nxlog" || log "Warning: Failed to remove init.d script"
    fi
    
    log "NXLog uninstallation completed."
    if [ -n "${BACKUP_DIR}" ] && [ -d "${BACKUP_DIR}" ]; then
        log "Configuration backup saved to: ${BACKUP_DIR}"
    fi
}

install_nxlog() {
    log "Starting NXLog CE installation..."
    
    # Check for configuration file
    if [ ! -f "${NX_CONF_SRC}" ]; then
        error_exit "Configuration file '${NX_CONF_SRC}' not found"
    fi
    
    # Create directories with proper error handling
    log "Creating necessary directories..."
    mkdir -p "${NX_ETC}/nxlog" || error_exit "Failed to create directory ${NX_ETC}/nxlog"
    mkdir -p "${NX_VAR}/run/nxlog" || error_exit "Failed to create directory ${NX_VAR}/run/nxlog"
    mkdir -p "${NX_VAR}/spool/nxlog" || error_exit "Failed to create directory ${NX_VAR}/spool/nxlog"
    
    # Copy configuration
    log "Copying configuration file to ${NX_ETC}/nxlog/${NX_CONF_FILE}..."
    cp "${NX_CONF_SRC}" "${NX_ETC}/nxlog/" || error_exit "Failed to copy configuration file"
    
    # Create PID file if it doesn't exist
    if [ ! -f "${NX_VAR}/run/nxlog/nxlog.pid" ]; then
        touch "${NX_VAR}/run/nxlog/nxlog.pid" || error_exit "Failed to create PID file"
    fi
    
    # Find NXLog source tarball
    NX_CE=$(find . -maxdepth 1 -name "nxlog-ce-*.tar.*" | head -1)
    if [ -z "${NX_CE}" ]; then
        error_exit "NXLog CE source tarball not found in current directory"
    fi
    log "Found NXLog CE source: ${NX_CE}"
    
    # Extract version from tarball name
    NX_VERSION=$(echo "${NX_CE}" | grep -oP 'nxlog-ce-\K[0-9.]+' || echo "3.0")
    NX_FOLDER="nxlog-ce-build"
    
    # Install dependencies
    install_deps
    
    # Extract and compile
    log "Extracting NXLog CE source code..."
    mkdir -p "${NX_FOLDER}" || error_exit "Failed to create build directory"
    tar -xf "${NX_CE}" -C "${NX_FOLDER}" --strip-components=1 || error_exit "Failed to extract source"
    
    log "Compiling NXLog CE ${NX_VERSION}..."
    cd "${NX_FOLDER}" || error_exit "Failed to change to build directory"
    ./autogen.sh || error_exit "Failed to run autogen.sh"
    ./configure --prefix="${NX_BASE}" || error_exit "Failed to configure build"
    make || error_exit "Failed to compile"
    make install || error_exit "Failed to install"
    
    # Return to original directory
    cd ..
    
    # Create systemd service if applicable
    if command -v systemctl >/dev/null 2>&1; then
        log "Creating systemd service..."
        cat > /etc/systemd/system/nxlog.service << EOF
[Unit]
Description=NXLog log collector
Documentation=https://nxlog.co/docs/
After=network.target

[Service]
Type=simple
ExecStart=${NX_BIN}/nxlog -f
ExecReload=${NX_BIN}/nxlog -r
Restart=on-failure
User=root
Group=root

[Install]
WantedBy=multi-user.target
EOF
        systemctl daemon-reload || log "Warning: Failed to reload systemd configuration"
        log "To enable NXLog service at startup, run: systemctl enable nxlog"
    fi
    
    # Remove dependencies if requested
    remove_deps
    
    log "Installation completed successfully!"
    log "Configuration file can be found at ${NX_ETC}/nxlog/${NX_CONF_FILE}"
    echo "NXLog CE ${NX_VERSION} has been installed successfully."
    echo "To start NXLog service, run: systemctl start nxlog  (if systemd is available)"
    echo "Or run directly: ${NX_BIN}/nxlog -f"
}

# Parse command line arguments
KEEP_DEPS=false
FORCE=false
while [ "$#" -gt 0 ]; do
    case "$1" in
        -h|--help)
            show_help
            ;;
        -i|--install)
            OPERATION="install"
            shift
            ;;
        -u|--uninstall)
            OPERATION="uninstall"
            shift
            ;;
        -k|--keep-deps)
            KEEP_DEPS=true
            shift
            ;;
        -b|--base-dir)
            NX_BASE="$2"
            NX_ETC="${NX_BASE}/etc"
            NX_VAR="${NX_BASE}/var"
            NX_BIN="${NX_BASE}/bin"
            shift 2
            ;;
        -f|--force)
            FORCE=true
            shift
            ;;
        *)
            error_exit "Unknown option: $1. Use --help for usage information."
            ;;
    esac
done

# Check if running as root
if [ "$(id -u)" -ne 0 ]; then
    error_exit "This script must be run as root"
fi

# Set up trap for cleanup
trap cleanup EXIT INT TERM

# Perform selected operation
case "${OPERATION}" in
    install)
        install_nxlog
        ;;
    uninstall)
        uninstall_nxlog
        ;;
    *)
        error_exit "Unknown operation: ${OPERATION}"
        ;;
esac
