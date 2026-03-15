# HID-Cpp

Windows Zero Trust HID attack prevention platform in modern C++20.

This project is designed for enterprise endpoint security against malicious HID behavior such as BadUSB, Rubber Ducky payload injection, hidden composite keyboard interfaces, and unauthorized USB devices.

## Current State

This repository is an implementation bootstrap (Phase 1 to 3) with a working userspace pipeline and placeholders for kernel driver integration.

Implemented now:

- USB HID enumeration via SetupAPI
- Lock-free event queue for low-latency hot path handling
- Device fingerprint generation with SHA-256 using Windows CNG
- Behavioral analysis with inter-keystroke timing features
- Two-stage classification structure:
	- Stage 1: rule-based pre-filter
	- Stage 2: ONNX pipeline stub with integrity verification gate
- Policy decision engine (allow, restrict, quarantine, block)
- Incident remediation playbook callback framework
- ETW provider registration and threat/device event emission
- End-to-end orchestration and executable entry point

## AI and ML Status

ML integration is wired and a baseline trained ONNX artifact can now be generated from the repository.

Available now:

- Training script: ml/train_hid_onnx.py
- Model artifact output: models/hid_stage2_model.onnx
- Integrity hash output: models/hid_stage2_model.sha256
- Metadata output: models/hid_stage2_model.meta.json
- Model integrity verification before use
- Stage 2 inference interface and fallback behavior

Run training:

```powershell
python .\ml\train_hid_onnx.py
```

Planned next:

- Replace synthetic training set with captured enterprise telemetry dataset
- Integrate full ONNX Runtime session execution in C++ inference path
- Add explainability feature output for SOC triage
- Add federated model delta update ingestion

## Security Design Principles

- Zero Trust default: no device is trusted at attach time
- Assume breach: design assumes attacker may have admin privileges
- Fail secure: timeouts and verification failures default to restricted or block
- Immutable forensics direction: event chain prepared for tamper-evident logging
- Minimal hot-path overhead: lock-free queue and bounded processing per stage

## Performance Targets

- Idle monitoring CPU overhead: at most 2%
- Legitimate input latency impact: less than 10 ms
- Stage 1 classification target: less than 1 ms per event
- Stage 2 ML path: invoked only for ambiguous events

## Repository Layout

- src/common: shared data types and lock-free queue
- src/platform: USB detection, HID monitor, ETW provider
- src/security: fingerprinting, behavior analysis, classification, policy, remediation, model integrity
- src/core: orchestrator for pipeline execution
- src/app: executable entry point
- docs: architecture and design references

## Build

Prerequisites:

- Windows 10 or Windows 11 development host
- Visual Studio 2022 C++ toolchain
- CMake available in PATH

PowerShell:

```powershell
cmake -S . -B build -G "Visual Studio 17 2022" -A x64
cmake --build build --config Release
```

Run:

```powershell
.\build\Release\hidshield.exe
```

## What Is Not Implemented Yet

- KMDF HID filter driver and IRP interception path
- IoRegisterPlugPlayNotification callbacks at kernel layer
- ObRegisterCallbacks handle protection in kernel mode
- CmRegisterCallback registry tamper monitoring
- Signed policy database with anti-rollback enforcement
- OCSF JSONL tamper-evident logging pipeline
- WFP-based network isolation and correlation actions
- Production REST API, SDK ABI layer, and PowerShell admin module

## Roadmap (Near Term)

1. Kernel driver skeleton and secure user-kernel IPC
2. Real raw-input ingestion and ETW process correlation
3. Signed/versioned policy store with ABAC support
4. Incident playbook actions for process kill, quarantine, and ticketing
5. ONNX Runtime integration and performance profiling against latency budget

## Development Notes

- Keep dependencies minimal and security-reviewed.
- Prefer Windows-native crypto and telemetry primitives.
- Preserve const-correctness and RAII patterns.
- Avoid raw new/delete in userspace code.

## Documentation

Architecture details are tracked in docs/ARCHITECTURE.md.
