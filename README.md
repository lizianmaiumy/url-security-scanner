# Web Security & SSL/TLS Validator (CLI)

A lightweight Python command-line utility designed to audit public web endpoints by inspecting HTTP security headers and analyzing SSL/TLS certificate lifecycles.

---

## 🎯 Overview

Web applications rely heavily on transport-layer encryption and defensive HTTP headers to mitigate attacks such as Man-in-the-Middle (MitM), Clickjacking, and Cross-Site Scripting (XSS). 

This project provides an automated, zero-friction diagnostic tool that connects to a target host, performs passive inspection of security headers against OWASP-recommended practices, and queries the remote socket to compute certificate validity.

---

## ✨ Features

- **HTTP Security Headers Inspection:** Audits the presence of essential defense-in-depth headers:
  - `Strict-Transport-Security` (HSTS)
  - `Content-Security-Policy` (CSP)
  - `X-Frame-Options`
  - `X-Content-Type-Options`
- **Low-Level SSL/TLS Certificate Analysis:**
  - Establishes a direct TCP socket on port 443 with TLS wrapping.
  - Extracts peer certificate metadata without relying on browser abstraction layers.
  - Calculates expiration deltas in UTC and flags expiring or expired certificates.
- **Resilient Execution:** Implements defensive exception handling (`requests.exceptions.RequestException`, socket timeouts) to prevent unhandled script crashes on dead or unreachable hosts.
- **CLI Interactivity:** Automatically normalizes domain and URL inputs directly from standard input.

---

## 🛠️ Architecture & Tech Stack

| Component | Technology | Purpose |
| :--- | :--- | :--- |
| **Language** | Python 3.10+ | Core scripting and execution |
| **HTTP Layer** | `requests` | Request dispatching, status code parsing, and header inspection |
| **TLS/Socket Layer** | `socket`, `ssl` (Standard Library) | Raw TCP connection & TLS handshake to extract peer certificates |
| **Date & Time Parsing** | `datetime` (Standard Library) | Expiration delta calculations with UTC awareness |

---

## 🚀 Getting Started

### Prerequisites

Ensure you have Python 3.10 or higher installed on your system:
```bash
python --version
```

### Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/SEU-USUARIO/url-security-scanner.git
   cd url-security-scanner
   ```

2. **Create and activate a virtual environment:**
   - **Windows (PowerShell):**
     ```powershell
     python -m venv venv
     .\venv\Scripts\Activate.ps1
     ```
   - **Linux / macOS:**
     ```bash
     python3 -m venv venv
     source venv/bin/activate
     ```

3. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

---

## 💻 Usage

Run the scanner directly from your terminal:

```bash
python scanner.py
```

When prompted, input any target domain or URL (e.g., `github.com` or `https://example.com`).

### Example Output

```text
==================================================
      VALIDADOR DE SEGURANÇA WEB (CLI)      
==================================================

Digite o domínio ou URL para analisar (ex: github.com): github.com

[+] Analisando cabeçalhos de segurança para: https://github.com
Status HTTP: 200 (OK)

--- Relatório de Cabeçalhos ---
[OK] Strict-Transport-Security: PRESENTE
[OK] Content-Security-Policy: PRESENTE
[OK] X-Frame-Options: PRESENTE
[OK] X-Content-Type-Options: PRESENTE

[+] Verificando Certificado SSL/TLS para: github.com
  - Emitido para: github.com
  - Expira em: 15/03/2027 às 23:59 UTC
  - Status: [OK] Válido por mais 125 dias.

==================================================
Análise concluída com sucesso.
```

---

## 📈 Roadmap

- [ ] Export audit reports to JSON or Markdown formats.
- [ ] Add batch domain scanning via `.txt` input files.
- [ ] Score target endpoints with a security rating (A to F).
- [ ] Integrate public reputation checks (e.g., AbuseIPDB / OpenPhish APIs).

---

## 📝 License

Distributed under the MIT License. See `LICENSE` for more information.