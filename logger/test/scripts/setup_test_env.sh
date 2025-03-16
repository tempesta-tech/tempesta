#!/bin/bash
#
# Tempesta FW service script.
#
# Copyright (C) 2014 NatSys Lab. (info@natsys-lab.com).
# Copyright (C) 2015-2024 Tempesta Technologies, Inc.
#
# This program is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License,
# or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
# FITNESS FOR A PARTICULAR PURPOSE.
# See the GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along with
# this program; if not, write to the Free Software Foundation, Inc., 59
# Temple Place - Suite 330, Boston, MA 02111-1307, USA.

set -euo pipefail

echo "=== TFW Logger Test Environment Setup ==="

# Get directories
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEST_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
LOGGER_DIR="$(cd "$TEST_DIR/.." && pwd)"

echo "Directories:"
echo "  Script: $SCRIPT_DIR"
echo "  Test:   $TEST_DIR"
echo "  Logger: $LOGGER_DIR"
echo

# Function to show colored output
log_info() {
        echo -e "\033[0;34m[INFO]\033[0m $1"
}

log_success() {
        echo -e "\033[0;32m[SUCCESS]\033[0m $1"
}

log_error() {
        echo -e "\033[0;31m[ERROR]\033[0m $1"
}

# Create test directories
log_info "Creating test directory structure..."
mkdir -p "$TEST_DIR"/{unit,integration,data,scripts}
mkdir -p "$TEST_DIR/data/test_configs"
log_success "Test directories created"

# Check and install system dependencies
log_info "Checking system dependencies..."
missing=()

if ! command -v g++ &>/dev/null; then
        missing+=("build-essential")
fi

if ! command -v cmake &>/dev/null; then
        missing+=("cmake")
fi

if ! pkg-config --exists gtest 2>/dev/null; then
        missing+=("libgtest-dev")
fi

if ! pkg-config --exists boost 2>/dev/null; then
        missing+=("libboost-all-dev")
fi

if ! command -v python3 &>/dev/null; then
        missing+=("python3")
fi

if ! command -v pip3 &>/dev/null; then
        missing+=("python3-pip")
fi

if [[ ${#missing[@]} -gt 0 ]]; then
        log_info "Installing missing dependencies: ${missing[*]}"
        sudo apt-get update
        sudo apt-get install -y "${missing[@]}" python3-venv pkg-config
        log_success "Dependencies installed"
else
        log_success "All dependencies already installed"
fi

# Build Google Test if needed
if [[ ! -f /usr/lib/x86_64-linux-gnu/libgtest.a ]] && [[ ! -f /usr/lib/libgtest.a ]]; then
        log_info "Building Google Test..."
        if [[ -d /usr/src/gtest ]]; then
                cd /usr/src/gtest
                sudo cmake .
                sudo make
                sudo cp lib/*.a /usr/lib/ 2>/dev/null || sudo cp lib*.a /usr/lib/
                cd "$LOGGER_DIR"
                log_success "Google Test built and installed"
        else
                log_info "Google Test source not found, trying alternative installation..."
                sudo apt-get install -y libgtest-dev libgmock-dev
        fi
fi

# Setup Python virtual environment
log_info "Setting up Python virtual environment..."
VENV_DIR="$TEST_DIR/venv"

if [[ -d "$VENV_DIR" ]]; then
        log_info "Virtual environment already exists"
else
        python3 -m venv "$VENV_DIR"
        log_success "Virtual environment created"
fi

# Activate and install Python packages
source "$VENV_DIR/bin/activate"
log_info "Installing Python test packages..."
pip install --quiet --upgrade pip
pip install --quiet pytest pytest-cov requests psutil click colorama
log_success "Python packages installed"

# Create basic test data files
log_info "Creating test data files..."

cat >"$TEST_DIR/data/valid_config.json" <<'JSON_EOF'
{
    "log_path": "/tmp/tfw_logger_test.log",
    "buffer_size": 8388608,
    "cpu_count": 2,
    "clickhouse": {
        "host": "localhost",
        "port": 9000,
        "user": "testuser",
        "password": "testpass",
        "max_events": 500,
        "max_wait_ms": 200
    }
}
JSON_EOF

cat >"$TEST_DIR/data/minimal_config.json" <<'JSON_EOF'
{
    "clickhouse": {
        "host": "localhost"
    }
}
JSON_EOF

log_success "Test data files created"

# Check if ClickHouse is available
log_info "Checking ClickHouse availability..."
if curl -s --connect-timeout 2 http://localhost:8123/ping &>/dev/null; then
        log_success "ClickHouse is available"
else
        log_info "ClickHouse not available (some integration tests will be skipped)"
        if command -v docker &>/dev/null; then
                log_info "You can start ClickHouse with:"
                echo "  docker run -d --name clickhouse-test -p 9000:9000 -p 8123:8123 clickhouse/clickhouse-server"
        fi
fi

# Check if tfw_logger binary exists
log_info "Checking tfw_logger binary..."
if [[ -f "$LOGGER_DIR/tfw_logger" ]]; then
        log_success "tfw_logger binary found"
else
        log_info "tfw_logger binary not found. Build it with:"
        echo "  cd $LOGGER_DIR && make build"
fi

echo
log_success "Test environment setup completed!"
echo
echo "Next steps:"
echo "1. Build tfw_logger: cd $LOGGER_DIR && make build"
echo "2. Run tests: make test"
echo "3. Run with device access: sudo make test-integration"
echo
