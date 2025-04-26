#!/bin/bash
# Enhanced NXLog CE installation/uninstallation script
# Purpose: Create required folders, compile NXLog CE, or uninstall it
# Supports: Debian, Ubuntu, Raspbian, Alpine, Rocky Linux, CentOS

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
DISABLE_PYTHON=false  # Default is to build with Python support

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
    echo "  -d, --debug      Show debug information during execution"
    echo "  -p, --no-python  Disable Python module support (fixes Python 3.11+ compatibility issues)"
    echo ""
    exit 0
}

install_deps() {
    log "Detecting distribution to install required dependencies..."
    
    # Get distribution information
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        DISTRO_NAME=$ID
        DISTRO_VERSION=$VERSION_ID
    else
        DISTRO_NAME=$(cat /etc/issue | awk '{print $1}')
    fi
    
    # Check for Raspberry Pi specifically
    IS_RASPBERRY_PI=false
    if [ -f /proc/device-tree/model ] && grep -q "Raspberry Pi" /proc/device-tree/model; then
        IS_RASPBERRY_PI=true
        log "Detected Raspberry Pi hardware"
    fi
    
    if [ "${DEBUG}" = "true" ]; then
        log "Debug: Detected distribution: ${DISTRO_NAME} ${DISTRO_VERSION}"
        log "Debug: Is Raspberry Pi: ${IS_RASPBERRY_PI}"
    fi
    
    case "${DISTRO_NAME}" in
        debian|ubuntu|raspbian)
            log "Detected Debian-based distribution."
            
            # More comprehensive dependencies for Debian-based systems, especially for Raspberry Pi
            DEBIAN_DEPS="build-essential libapr1-dev libpcre3-dev libssl-dev libexpat1-dev autoconf automake libtool pkg-config libdbi-dev flex bison"
            
            # Add Python dev package if Python modules are enabled
            if [ "${DISABLE_PYTHON}" != "true" ]; then
                DEBIAN_DEPS="${DEBIAN_DEPS} python3-dev"
            fi
            
            # Extra dependencies for Raspbian or Raspberry Pi running Debian/Ubuntu
            if [ "${IS_RASPBERRY_PI}" = "true" ] || [ "${DISTRO_NAME}" = "raspbian" ]; then
                DEBIAN_DEPS="${DEBIAN_DEPS} libtool-bin"
                log "Adding extra dependencies for Raspberry Pi"
            fi
            
            log "Installing dependencies: ${DEBIAN_DEPS}"
            apt-get update || error_exit "Failed to update package lists"
            apt-get install -y ${DEBIAN_DEPS} || error_exit "Failed to install dependencies"
            
            # Only remove the core build essentials when finished, leave libraries
            REMOVE_CMD="apt-get remove -y build-essential autoconf automake libtool flex bison"
            ;;
        alpine)
            log "Detected Alpine Linux."
            ALPINE_DEPS="make g++ tar apr-dev openssl-dev pcre-dev libdbi-dev openssl expat-dev zlib-dev perl perl-dev file python3-dev autoconf automake libtool"
            # Add Python dev package if Python modules are enabled
            if [ "${DISABLE_PYTHON}" != "true" ]; then
                ALPINE_DEPS="${ALPINE_DEPS} python3-dev"
            fi
            
            apk add --no-cache ${ALPINE_DEPS} || error_exit "Failed to install dependencies"
            REMOVE_CMD="apk del make g++ autoconf automake libtool"
            ;;
        rocky|centos|rhel|fedora)
            log "Detected RPM-based distribution."
            
            RHEL_DEPS="gcc apr-devel pcre-devel openssl-devel expat-devel make automake libtool pkgconfig libdbi-devel flex bison"
            
            # Add Python dev package if Python modules are enabled
            if [ "${DISABLE_PYTHON}" != "true" ]; then
                RHEL_DEPS="${RHEL_DEPS} python3-devel"
            fi
            
            yum install -y ${RHEL_DEPS} || error_exit "Failed to install dependencies"
            REMOVE_CMD="yum remove -y gcc automake libtool flex bison"
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
    
    # Also check libexec directory (where modules are installed)
    if [ -d "${NX_BASE}/libexec/nxlog" ]; then
        rm -rf "${NX_BASE}/libexec/nxlog" || log "Warning: Failed to remove ${NX_BASE}/libexec/nxlog"
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
    
    # Check if required tools are available
    log "Checking for required build tools..."
    for TOOL in autoconf automake make gcc; do
        if ! command -v ${TOOL} >/dev/null 2>&1; then
            error_exit "Required build tool ${TOOL} is missing. Please install it and try again."
        fi
    done
    
    # Special handling for libtoolize vs libtool
    if ! command -v libtoolize >/dev/null 2>&1; then
        if command -v libtool >/dev/null 2>&1; then
            log "Using libtool instead of libtoolize..."
            # Some systems use libtool instead of libtoolize
            if grep -q "libtoolize" ./autogen.sh; then
                log "Patching autogen.sh to use libtool instead of libtoolize..."
                sed -i 's/libtoolize/libtool/g' ./autogen.sh
            fi
        else
            error_exit "Neither libtoolize nor libtool is available. Please install libtool package."
        fi
    fi
    
    # Handle Python dependency requirement
    log "Running Python fix script"

    SOURCE_FILE="src/modules/extension/python/libnxpython.c"

    # Get Python version
    PYTHON_VERSION=$(python3 --version 2>&1 | awk '{print $2}')
    PYTHON_MAJOR=$(echo "$PYTHON_VERSION" | cut -d. -f1)
    PYTHON_MINOR=$(echo "$PYTHON_VERSION" | cut -d. -f2)

    echo "[INFO] Detected Python version: $PYTHON_MAJOR.$PYTHON_MINOR"

    # Check if Python is >= 3.11
    if [[ "$PYTHON_MAJOR" -gt 3 ]] || { [[ "$PYTHON_MAJOR" -eq 3 && "$PYTHON_MINOR" -ge 11 ]]; }; then
        if grep -q "PyFrame_GetCode" "$SOURCE_FILE"; then
            echo "[INFO] Patch already present. No action needed."
        else
            echo "[INFO] Python >= 3.11 detected. Patching $SOURCE_FILE..."
            cp "$SOURCE_FILE" "${SOURCE_FILE}.bak"

            sed -i \
                -e 's/frame->f_code/PyFrame_GetCode(frame)/g' \
                -e 's/frame->f_back/PyFrame_GetBack(frame)/g' \
                -e 's/frame->f_lasti/PyFrame_GetLasti(frame)/g' \
                "$SOURCE_FILE"

            echo "[INFO] Patch applied successfully."
        fi
    else
        echo "[INFO] Python version < 3.11. Skipping patch."
    fi

    # Special handling for autogen.sh
    log "Running autogen.sh..."
    chmod +x ./autogen.sh
    if [ "${DEBUG}" = "true" ]; then
        ./autogen.sh || error_exit "Failed to run autogen.sh"
    else
        ./autogen.sh >/dev/null 2>&1 || error_exit "Failed to run autogen.sh"
    fi
    
    # Configure with or without Python support
    log "Configuring build..."
    CONFIGURE_OPTS="--prefix=${NX_BASE}"
    
    if [ "${DISABLE_PYTHON}" = "true" ]; then
        log "Disabling Python module support as requested..."
        CONFIGURE_OPTS="${CONFIGURE_OPTS} --disable-python-module"
    else
        # Check Python version
        PY_VER=$(python3 --version 2>&1 | cut -d' ' -f2 | cut -d'.' -f1-2)
        log "Detected Python version: ${PY_VER}"
        
        # If Python 3.11 or higher, disable Python module
        if [ "$(echo "${PY_VER}" | sed 's/\.//g')" -ge "311" ]; then
            log "Detected Python 3.11 or newer, which is incompatible with NXLog Python module."
            log "Automatically disabling Python module support to fix compilation errors."
            CONFIGURE_OPTS="${CONFIGURE_OPTS} --disable-python-module"
        fi
    fi
    
    # Print configuration options when debug is enabled
    if [ "${DEBUG}" = "true" ]; then
        log "Configure options: ${CONFIGURE_OPTS}"
    fi
    
    # Run configure with appropriate options
    ./configure ${CONFIGURE_OPTS} || error_exit "Failed to configure build"
    
    log "Compiling source code..."
    make || error_exit "Failed to compile"
    
    log "Installing NXLog..."
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
    
    if [ "${DISABLE_PYTHON}" = "true" ] || [ "$(echo "${PY_VER}" | sed 's/\.//g')" -ge "311" ]; then
        echo ""
        echo "NOTE: Python module support was disabled during compilation."
        echo "      Python-based input, processor, and output modules will not be available."
    fi
}

# Parse command line arguments
KEEP_DEPS=false
FORCE=false
DEBUG=false
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
        -d|--debug)
            DEBUG=true
            shift
            ;;
        -p|--no-python)
            DISABLE_PYTHON=true
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
