# TFW Logger Tests

Comprehensive test suite for `tfw_logger` component of Tempesta FW.

## 🚀 Quick Start

```bash
# Setup (one time)
./test/scripts/setup_test_env.sh

# Standard workflow
make build
make test

# Specific tests
make test-unit
make test-integration

# With permissions
sudo make test-integration
```

## 📁 Test Structure

```
test/
├── unit/				# C++ Unit tests
│   └── test_config.cc			# Configuration management tests
├── integration/			# Python Integration tests  
│   ├── test_logger.py			# Basic tfw_logger functionality
│   └── test_running_integration.py 	# Process & device interaction
├── data/				# Test configuration files
├── scripts/				# Helper scripts
│   └── setup_test_env.sh		# Environment setup
└── venv/				# Python virtual environment
```

## 🧪 What Gets Tested

### ✅ Unit Tests (C++)
- JSON configuration parsing & validation
- Command line argument processing
- File I/O operations
- Error handling & recovery

### ✅ Integration Tests (Python)
- Process lifecycle management
- Background execution & graceful shutdown
- mmap device access & permissions
- CPU affinity configuration
- CLI parameter validation
- Tempesta.sh integration

## 📊 Test Results

- **7 Unit Tests** - Configuration management
- **17+ Integration Tests** - Process interaction, device access, CLI validation

## 🔧 Requirements

### System Dependencies
- `libgtest-dev` - Google Test framework
- `libboost-all-dev` - Boost libraries  
- `python3-venv` - Python virtual environment
- `build-essential` - C++ compiler

### Runtime Requirements
- **Tempesta FW modules** (for device tests)
- **Root privileges** (for `/dev/tempesta_mmap_log` access)
- **ClickHouse server** (optional, for full integration)

## 🏃‍♂️ Running Tests

| Command | Description |
|---------|-------------|
| `make test` | Run all tests (unit + integration) |
| `make test-unit` | C++ unit tests only |
| `make test-integration` | Python integration tests |
| `sudo make test-integration` | Integration tests with device access |

## 🐛 Troubleshooting

### Common Issues

**"Tempesta mmap device not available"**
```bash
# Start Tempesta FW to create device
sudo ../scripts/tempesta.sh --start
```

**"Permission denied: /dev/tempesta_mmap_log"**
```bash
# Run integration tests with sudo
sudo make test-integration
```

**"Binary not found"**
```bash
# Build tfw_logger first
make build
```

**Missing dependencies**
```bash
# Run setup again
./test/scripts/setup_test_env.sh
```

### Test Status Meanings
- ✅ **PASSED** - Test successful
- ❌ **FAILED** - Test failed, check error output
- ⏭️ **SKIPPED** - Missing dependencies (normal)
