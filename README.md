# Hardened XZ Utils — Cybersecurity & Cyberforensics Assignment

**Student:** yantra00  
**Platform:** macOS (Apple Silicon), cross-platform C  
**Base Tool:** XZ Utils v5.4.6 (https://github.com/tukaani-project/xz)  
**Assignment Type:** Security hardening of an open-source compression utility

---

## 1. Introduction

XZ Utils is a widely used open-source data compression tool found on virtually every Linux and macOS system. It implements the LZMA2 compression algorithm and is the tool behind `.xz` files — a format commonly used in Linux package distribution, log archiving, and software releases.

In early 2024, XZ Utils became the subject of one of the most sophisticated supply chain attacks ever discovered (CVE-2024-3094). A malicious actor, operating under a fake identity over two years, inserted a backdoor into XZ versions 5.6.0 and 5.6.1. The backdoor specifically targeted SSH authentication on systemd-based Linux distributions, allowing remote code execution without a valid password. It was discovered almost by accident by a Microsoft engineer who noticed unusual CPU usage.

This incident highlighted a critical problem: widely trusted system tools often lack even basic security hardening. This project addresses that gap by cloning XZ Utils and adding a security wrapper layer with four key features.

---

## 2. Problem Statement

The standard `xz` tool, despite being a critical system utility, has the following security weaknesses:

- **No input validation** — it will attempt to process any path given to it, including paths that could cause path traversal attacks (e.g. `../../../etc/passwd`)
- **No access control checks** — it does not verify file ownership, permissions, or whether a file has suspicious attributes like SUID/SGID bits or world-writable permissions
- **No integrity verification** — there is no built-in mechanism to record or verify the hash of files before and after compression, making tampering undetectable
- **No audit trail** — there is no logging of who ran the tool, on which file, at what time, or what the result was

These gaps are particularly dangerous in shared server environments, automated pipelines, and forensic workflows where file integrity and accountability are critical.

---

## 3. Project Goal

Clone XZ Utils and build a security wrapper (`secure_xz`) in C that intercepts all compression and decompression operations and enforces four security controls before passing execution to the real `xz` binary.

The tool must work cross-platform (macOS and Linux) and demonstrate each security feature with concrete terminal output.

---

## 4. Repository Structure

```
hardened-xz/
├── xz/                        # Upstream XZ Utils (cloned from GitHub, tag v5.4.6)
├── security/
│   ├── secure_xz.c            # Main entry point — chains all 4 security checks
│   ├── input_validator.c/.h   # Feature 1: Input validation & sanitization
│   ├── integrity_checker.c/.h # Feature 2: SHA-256 integrity checking
│   ├── access_control.c/.h    # Feature 3: File access control checks
│   └── audit_logger.c/.h      # Feature 4: Append-only audit logging
└── secure_xz                  # Compiled binary
```

---

## 5. Security Features Implemented

### 5.1 Feature 1 — Input Validation & Sanitization (`input_validator.c`)

**What it does:** Before any file is processed, the validator checks the input path and file for a set of known dangerous patterns.

**Checks performed:**
- Null path guard — rejects null pointers immediately
- Null byte injection — scans the path string for embedded null bytes, a classic technique for bypassing extension checks
- Path traversal detection — rejects any path containing `../` or `..\`, preventing attackers from redirecting the tool to sensitive system files
- Extension enforcement — when compressing, rejects files already ending in `.xz`; when decompressing, requires `.xz` or `.lzma`
- File existence and size — confirms the file exists and rejects files over 512 MB

**Why it matters:** Without this check, a user or script could pass `../../../etc/passwd` as the target file. The standard `xz` would attempt to compress it. The validator catches and rejects this before any file I/O occurs.

**Terminal demonstration:**
```
$ ./secure_xz compress ../../../etc/passwd
[SECURITY] Input validation failed: Path traversal detected

$ ./secure_xz compress test.txt.xz
[SECURITY] Input validation failed: Unexpected file extension

$ ./secure_xz compress ghost.txt
[SECURITY] Input validation failed: File not found
```

---

### 5.2 Feature 2 — Integrity Checking (`integrity_checker.c`)

**What it does:** Before compression, computes a SHA-256 hash of the input file using the OpenSSL EVP API (the modern, non-deprecated interface in OpenSSL 3.x). The hash is stored in a sidecar file alongside the compressed output.

**Files created:**
- `filename.xz` — the compressed output
- `filename.txt.sha256` — a sidecar file containing the SHA-256 hash and original filename

**Why it matters:** In forensic and security workflows, being able to prove that a file has not been modified is essential. The sidecar hash provides a tamper-evident record. If the original file is later altered, the hash will not match. The hash is also recorded in the audit log, creating a permanent timestamped record of the file's state at the time of compression.

**Terminal demonstration:**
```
$ cat test.txt.sha256
638f0b994720ff861bb8db2f9db27e9dd1b9bf5e5da273637e983b3b1b6e86b2  test.txt
```

**Implementation note:** The original implementation used the deprecated `SHA256_Init/Update/Final` API. This was updated to use `EVP_DigestInit_ex`, `EVP_DigestUpdate`, and `EVP_DigestFinal_ex` from `<openssl/evp.h>`, which is the correct approach for OpenSSL 3.x.

---

### 5.3 Feature 3 — Access Control (`access_control.c`)

**What it does:** Checks the file's metadata using `lstat()` and `stat()` system calls before allowing the operation to proceed.

**Checks performed:**
- Symlink detection — uses `lstat()` to detect symbolic links, which are a common vector for TOCTOU (Time-of-Check-Time-of-Use) attacks where an attacker swaps a file between the security check and the actual operation
- World-writable check — rejects files with the `S_IWOTH` bit set, as these could be modified by any user on the system
- SUID/SGID check — rejects files with the setuid or setgid bit set, which are unusual and potentially dangerous attributes for data files
- Read permission check — verifies the calling user has read access using `access(filepath, R_OK)`

**Why it matters:** A world-writable file could be modified by another process between the time it is hashed and the time it is compressed. A symlink could point to a completely different file than the user expects. These checks prevent a class of subtle attacks that are invisible to basic file operations.

---

### 5.4 Feature 4 — Audit Logging (`audit_logger.c`)

**What it does:** After every security check and after the final xz operation, appends a structured log entry to `~/.xz_audit.log`. The log is append-only and written with `fopen(..., "a")`.

**Each log entry records:**
- ISO 8601 timestamp
- Username (from `getpwuid(getuid())`)
- Operation type (VALIDATE, ACCESS_CHECK, COMPRESS, DECOMPRESS)
- File path
- SHA-256 hash (where available)
- Result (SUCCESS, FAILURE, or DENIED)
- Detail message

**Why it matters:** In a security incident, the audit log provides a forensic record of every file operation. If a file was tampered with after compression, the log shows the original hash. If an attacker attempted a path traversal, the log records the denied attempt. In shared or multi-user environments, the log also shows which user performed which operation.

**Terminal demonstration:**
```
$ cat ~/.xz_audit.log
[2026-05-10T19:46:06] user=yantra00 op=VALIDATE file=test.txt hash=N/A result=SUCCESS detail=Input validation passed
[2026-05-10T19:46:06] user=yantra00 op=ACCESS_CHECK file=test.txt hash=N/A result=SUCCESS detail=Access control passed
[2026-05-10T19:46:06] user=yantra00 op=COMPRESS file=test.txt hash=638f0b994720ff861bb8db2f9db27e9dd1b9bf5e5da273637e983b3b1b6e86b2 result=SUCCESS detail=Pre-op hash computed
[2026-05-10T19:46:09] user=yantra00 op=COMPRESS file=test.txt hash=638f0b994720ff861bb8db2f9db27e9dd1b9bf5e5da273637e983b3b1b6e86b2 result=SUCCESS detail=xz completed OK
```

---

## 6. How the Components Connect (`secure_xz.c`)

`secure_xz.c` is the main entry point. It accepts two arguments — the operation (`compress` or `decompress`) and the file path — and runs each security module in order:

```
User input
    │
    ▼
[1] Input Validation     ──── FAIL ──▶ Print error, log DENIED, exit
    │ PASS
    ▼
[2] Access Control       ──── FAIL ──▶ Print error, log DENIED, exit
    │ PASS
    ▼
[3] SHA-256 Hash computed and logged
    │
    ▼
[4] Real xz runs
    │
    ▼
[5] Audit log updated with final result (SUCCESS or FAILURE)
```

If any check fails, the tool exits immediately and never reaches `xz`. All outcomes — including blocked attempts — are recorded in the audit log.

---

## 7. Build Instructions

### macOS (Apple Silicon / Intel)

```zsh
# Install dependencies
brew install openssl xz

# Build
gcc -Wall -Wextra -o secure_xz \
    security/secure_xz.c \
    security/input_validator.c \
    security/integrity_checker.c \
    security/access_control.c \
    security/audit_logger.c \
    -I$(brew --prefix openssl)/include \
    -L$(brew --prefix openssl)/lib \
    -lssl -lcrypto
```

### Linux (Ubuntu/Debian)

```bash
sudo apt install libssl-dev xz-utils
gcc -Wall -Wextra -o secure_xz \
    security/secure_xz.c \
    security/input_validator.c \
    security/integrity_checker.c \
    security/access_control.c \
    security/audit_logger.c \
    -lssl -lcrypto
```

---

## 8. Test Results

All tests run on macOS (Apple Silicon), XZ Utils v5.4.6, OpenSSL 3.x.

| Test | Command | Expected | Result |
|------|---------|----------|--------|
| Normal compress | `./secure_xz compress test.txt` | Creates .xz + .sha256, logs SUCCESS | ✅ Pass |
| Audit log written | `cat ~/.xz_audit.log` | Timestamped entries with hash | ✅ Pass |
| Path traversal blocked | `./secure_xz compress ../../../etc/passwd` | Input validation failed | ✅ Blocked |
| Bad extension blocked | `./secure_xz compress test.txt.xz` | Unexpected file extension | ✅ Blocked |
| Ghost file blocked | `./secure_xz compress ghost.txt` | File not found | ✅ Blocked |
| Decompress (file exists) | `./secure_xz decompress test.txt.xz` | xz refused to overwrite — logged as FAILURE | ✅ Expected behaviour |

---

## 9. Relevance to CVE-2024-3094 (XZ Backdoor)

This project is directly motivated by the XZ supply chain attack discovered in March 2024. A threat actor introduced malicious code into XZ versions 5.6.0 and 5.6.1 that bypassed SSH authentication. The attack went undetected for months.

The security features added in this project would contribute to detecting such attacks:

- **Integrity checking** — if the XZ binary itself were modified (as in the backdoor), a hash of the binary before and after would detect the change
- **Audit logging** — unexpected operations (e.g. the tool attempting to access SSH-related files) would appear in the log
- **Access control** — checks on SUID/SGID bits and symlinks would flag unusual file states introduced by an attacker

This project demonstrates that even simple security hardening applied as a wrapper layer can significantly reduce the attack surface of a widely trusted tool.

---

## 10. Conclusion

This project successfully implemented four security features on top of XZ Utils: input validation, integrity checking, access control, and audit logging. Each feature was demonstrated with terminal output showing both successful operations and blocked attack attempts. The implementation is written in C, uses the OpenSSL EVP API for cryptographic hashing, and is cross-platform across macOS and Linux.

The project reinforces a core principle of defensive security: trust nothing, validate everything, and leave a paper trail.
