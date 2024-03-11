# Changelog for Tarian Detector

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased](https://github.com/intelops/tarian-detector/tree/main) - 03-07-2024

### Added

- No specific changes in this release.

## [v0.1.0](https://github.com/intelops/tarian-detector/releases/tag/0.1.0) - 03-04-2024

### Added in 0.1.0

- Initial setup of the repository and project structure.
- Placeholder for initial release notes.
- eBPF kprobe and kretprobe hooks for following syscalls
  1. `__x64_sys_execve`
  2. `__x64_sys_execveat`
  3. `__x64_sys_clone`
  4. `__x64_sys_read`
  5. `__x64_sys_readv`
  6. `__x64_sys_write`
  7. `__x64_sys_writev`
  8. `__x64_sys_close`
  9. `__x64_sys_open`
  10. `__x64_sys_openat`
  11. `__x64_sys_openat2`
  12. `__x64_sys_accept`
  13. `__x64_sys_connect`
  14. `__x64_sys_listen`
  15. `__x64_sys_bind`
  16. `__x64_sys_socket`
- eBPF perf event array map for sharing data from kernel to user space.
- The statistics mechanism at kernel space keeps track of the following:
  - Number of times programs are triggered.
  - Number of successful triggers sent to userspace.
  - Number of triggers failed to be sent to userspace.
  - Number of error-specific failed triggers.
- Support for multiple eBPF program types:
  - Kprobe
  - Kretprobe
  - Tracepoint
  - Raw tracepoint
  - Cgroup
- Support for multiple eBPF map types
  - Ringbuf
  - Perf event array
  - Array of ringbuf
- The statistics mechanism at userspace keeps track of the following:
  - Number of events received from kernel space.
  - Number of probe-specific events received from kernel space.

### Changed in v0.1.0

- Updated documents to reflect latest changes.

## Types of changes

- `Added` for new features.
- `Changed` for changes in existing functionality.
- `Deprecated` for soon-to-be removed features.
- `Removed` for now removed features.
- `Fixed` for any bug fixes.
- `Security` in case of vulnerabilities.
