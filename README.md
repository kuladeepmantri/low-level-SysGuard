# SysGuard
[![CMake Build](https://github.com/kuladeepmantri/low-level-SysGuard/actions/workflows/cmake-single-platform.yml/badge.svg)](https://github.com/kuladeepmantri/low-level-SysGuard/actions/workflows/cmake-single-platform.yml)
[![Website](https://img.shields.io/badge/Website-Live_Demo-blue?style=flat&logo=next.js)](https://kuladeepmantri.github.io/low-level-SysGuard/)

**ARM Linux Syscall Tracer & Security Analyzer**

[**View Live Website & Demo**](https://kuladeepmantri.github.io/low-level-SysGuard/)

SysGuard is a production-quality command-line security application for ARM64 Linux containers. It provides syscall tracing, behavioral profiling, adaptive policy enforcement, and AI-assisted security analysis.

## Features

- **Syscall Tracing**: Trace target programs using ptrace, capturing detailed syscall metadata including arguments, return values, and timing
- **Behavioral Profiling**: Build baseline profiles from traces to characterize normal program behavior
- **Anomaly Detection**: Compare runtime behavior against baselines to detect deviations
- **Data Flow Analysis**: Track sensitive data flow and detect potential exfiltration patterns
- **Activity Graph**: Model process/file/network activity as a graph for visualization and analysis
- **Policy Engine**: Generate and enforce restrictive syscall policies with alert or block modes
- **AI Integration**: Optional integration with local LLM services for natural language security analysis

## Requirements

- ARM64 Linux (designed for container environments)
- CMake 3.16+
- GCC or Clang with C11 support
- libcurl (for AI integration)
- json-c (for JSON serialization)
- Check (for unit tests, optional)

## Building

### Using Docker (Recommended)

```bash
# Build the container
docker build --platform linux/arm64 -t sysguard .

# Run with access to trace processes
docker run --platform linux/arm64 --cap-add=SYS_PTRACE --security-opt seccomp=unconfined -it sysguard
```

### Native Build

```bash
mkdir build && cd build
cmake ..
make -j$(nproc)

# Run tests
make test

# Install
sudo make install
```

## Usage

### Learn Mode - Trace a Program

```bash
# Trace a program and save the syscall trace
sysguard learn -- /bin/ls -la

# Trace with custom trace ID
sysguard learn -t my-trace-id -- ./myapp arg1 arg2
```

### Profile Mode - Build Behavioral Profile

```bash
# Build profile from a trace
sysguard profile -t <trace-id>

# View existing profile
sysguard profile -p <profile-id>
```

### Compare Mode - Detect Anomalies

```bash
# Compare a new run against baseline
sysguard compare -p <profile-id> -- ./myapp

# Compare existing trace against baseline
sysguard compare -p <profile-id> -t <trace-id>
```

### Policy Mode - Generate Security Policy

```bash
# Generate policy from profile
sysguard policy -p <profile-id>

# Generate minimal policy (essential syscalls only)
sysguard policy

# View existing policy
sysguard policy -P <policy-id>
```

### Enforce Mode - Run Under Policy

```bash
# Run with alert mode (log violations but allow)
sysguard enforce -P <policy-id> -m alert -- ./myapp

# Run with block mode (prevent policy violations)
sysguard enforce -P <policy-id> -m block -- ./myapp
```

### Analyze Mode - AI Analysis

```bash
# Analyze profile with AI
sysguard analyze -p <profile-id> -a http://localhost:11434/api/generate -M llama2
```

## Options

| Option | Description |
|--------|-------------|
| `-h, --help` | Show help message |
| `-V, --version` | Show version |
| `-v, --verbose` | Verbose output |
| `-q, --quiet` | Quiet mode |
| `-j, --json` | Output in JSON format |
| `-d, --data-dir DIR` | Data directory (default: /data/sysguard) |
| `-t, --trace-id ID` | Trace ID to use |
| `-p, --profile-id ID` | Profile ID to use |
| `-P, --policy-id ID` | Policy ID to use |
| `-o, --output FILE` | Output file path |
| `-m, --mode MODE` | Enforcement mode: alert or block |
| `-a, --ai-endpoint URL` | AI service endpoint |
| `-M, --ai-model MODEL` | AI model name |

## Data Storage

SysGuard stores all data in the data directory (default: `/data/sysguard`):

```
/data/sysguard/
├── traces/      # Syscall traces (JSON)
├── profiles/    # Behavioral profiles (JSON)
└── policies/    # Security policies (JSON)
```

## Security Considerations

- SysGuard requires `CAP_SYS_PTRACE` capability to trace processes
- In Docker, use `--cap-add=SYS_PTRACE --security-opt seccomp=unconfined`
- Block mode enforcement can terminate processes - use with caution
- Sensitive path detection includes common credential and key locations
- AI integration sends profile/trace data to the configured endpoint

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                         CLI Layer                           │
├─────────────────────────────────────────────────────────────┤
│  Learn  │  Profile  │  Compare  │  Policy  │ Enforce │ AI  │
├─────────────────────────────────────────────────────────────┤
│                      Core Components                        │
├──────────┬──────────┬──────────┬──────────┬────────────────┤
│  Tracer  │ Profiler │ DataFlow │  Graph   │    Policy      │
│ (ptrace) │          │ Analyzer │  Model   │    Engine      │
├──────────┴──────────┴──────────┴──────────┴────────────────┤
│                    Storage Layer (JSON)                     │
├─────────────────────────────────────────────────────────────┤
│                    ARM64 Linux / ptrace                     │
└─────────────────────────────────────────────────────────────┘
```

## Testing

```bash
# Run all tests
cd build && ctest --output-on-failure

# Run specific test suite
./tests/sysguard_tests
```

## License

MIT License

## Contributing

Contributions are welcome. Please ensure:
- Code follows existing style
- All tests pass
- New features include tests
- Documentation is updated
