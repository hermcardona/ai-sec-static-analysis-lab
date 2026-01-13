# Secure AI Development with Static Analysis

This repository demonstrates how static analysis tools can be used to identify
and remediate security vulnerabilities commonly found in AI / ML codebases.

The focus is on **AI-specific risks** that traditional testing often misses,
such as insecure model deserialization and improper handling of secrets.

---

## 🎯 Objectives

- Identify AI-related security flaws using static analysis
- Remediate insecure patterns using secure-by-design techniques
- Validate fixes through repeatable, automated scans
- Demonstrate professional AppSec workflows for AI systems

---

## 🔍 Threat Model Highlights

The lab addresses the following high-risk patterns:

- **Insecure model deserialization**
  - Use of `pickle.load()` on untrusted artifacts
  - Risk: Arbitrary code execution (CWE-502)

- **Hardcoded secrets**
  - API keys and database credentials embedded in source code
  - Risk: Credential leakage and lateral movement (CWE-259)

- **Path traversal risks**
  - User-controlled input used to construct file paths
  - Risk: Unauthorized file access

---

## 🛠 Tools Used

- **Bandit** – Python security static analysis
- **Semgrep (OSS)** – Pattern-based code scanning with custom rules
- **PyLint** – Code quality and correctness analysis
- **Python 3.13** – Runtime environment

---

## 🔐 Key Remediations Implemented

- Removed unsafe pickle-based deserialization paths
- Replaced model loading with integrity-checked, non-executable artifacts
- Migrated secrets to environment variables
- Used `# nosec` annotations sparingly and with documented justification
- Verified fixes by re-running all static analysis tools

---

## ▶️ How to Run the Scans

### Create and activate virtual environment
```bash
python -m venv .venv
source .venv/bin/activate
