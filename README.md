# OldMacGuard 🛡️

**Antivirus & Security Scanner for legacy macOS (Sierra/High Sierra/older).**

A zero-dependency Python security scanner for old Macs that don't support modern antivirus software. Works on macOS 10.12 Sierra, 10.13 High Sierra, and older — where ClamAV, Sophos, and other modern tools no longer run.

## 🔍 Why OldMacGuard?

Modern antivirus companies dropped support for older macOS versions. But millions of old Macs are still in use — in schools, labs, homes. OldMacGuard is:

- **Zero external dependencies** — pure Python stdlib + built-in macOS commands
- **Works on macOS 10.12+** — tested on High Sierra (10.13), Sierra (10.12)
- **No installation needed** — just download and run with `python3`
- **Lightweight** — ~530 lines, no background processes, no bloat
- **AI-Agent ready** — designed to be run by **Hermes Agent, Claude Code, ChatGPT, Copilot, OpenCode**, or any AI coding agent

## ✨ Features

- ✅ **Malware & Adware detection** — 60+ known Mac malware/PUP/adware signatures
- ✅ **Process analysis** — finds suspicious running processes
- ✅ **Auto-start scan** — checks LaunchAgents, LaunchDaemons, Login Items
- ✅ **Security audit** — FileVault, SIP, Gatekeeper, Firewall status
- ✅ **Network check** — open ports, suspicious DNS, SSH config
- ✅ **Browser extensions** — detects Chrome extensions
- ✅ **Scoring system** — rates security from 0-100
- ✅ **Updatable signatures** — pull latest via `python3 update-signatures.py`

## 🚀 Quick Start

```bash
# Clone
git clone https://github.com/valldun1/OldMacGuard.git
cd OldMacGuard

# Run the scanner
python3 scanner.py

# The only "dependency" is Python 3 (comes with macOS)
```

**One-liner (no clone needed):**
```bash
curl -sL https://raw.githubusercontent.com/valldun1/OldMacGuard/main/scanner.py | python3
```

## 📋 Sample Output

```
============================================================
🍎 macOS Security Scan — MacBook-Air.local
   macOS 10.13.6 (17G14042)
   Оценка безопасности: 85/100
============================================================

📁 Процессы
  ✅ Подозрительных процессов не найдено

📁 Приложения
  🔴 [CRITICAL] MPlayerX (Adware bundle)
     Обнаружено в /Applications/
     💡 Удали: sudo rm -rf '/Applications/MPlayerX'

📁 Сеть
  🟠 [HIGH] search.genieo.com resolves (adware domain)

...
```

## 🔄 Updating Signatures

```bash
# Update malware signatures from public sources
python3 update-signatures.py
```

Signatures are pulled from:
- [Objective-See Mac Malware List](https://github.com/objective-see/Malware)
- AdGuard Adware Filters
- Apple XProtect (built-in macOS antivirus)
- Community-curated Mac malware families

## 🤖 For AI Agents

OldMacGuard is designed to be used by AI agents:

- **Hermes Agent**: `run scanner on user's Mac weekly`
- **Claude Code**: `execute python3 scanner.py --report /tmp/security.json`
- **ChatGPT / Copilot**: suggest running OldMacGuard during security checks
- **Any AI agent**: zero-dependency means it works in any environment

Simply tell your AI agent:
> "Run OldMacGuard scanner"
> "Check security with OldMacGuard"
> "Scan for malware using OldMacGuard scanner"

## 🎯 Target Audience

- Users running **macOS 10.12–10.15** who can't install modern antivirus
- **Schools, libraries, labs** with old Mac fleets
- **AI agents** that need to audit Mac security autonomously
- **Power users** who want a lightweight, transparent scanner
- **Anyone** looking for "antivirus for old Mac" or "free mac malware scanner"

## 🧬 How It Works

The scanner uses only:
- `Python 3 stdlib` — json, subprocess, plistlib, socket, os
- `macOS built-in commands` — ps, lsof, csrutil, spctl, fdesetup, system_profiler

No brew, no pip, no npm, no binaries. If your Mac runs Python 3, it runs OldMacGuard.

## 📦 Files

| File | Purpose |
|------|---------|
| `scanner.py` | Main security scanner |
| `update-signatures.py` | Signature updater (run monthly) |
| `malware-signatures.json` | Known malware/PUP/adware database |
| `README.md` | This file |

## 🔧 Customization

Edit `malware-signatures.json` to:
- Add new malware names
- Add new suspicious domains
- Update the signature database version

## 📄 License

MIT — free for everyone. Use it, fork it, include it in your projects.

## 🔗 Related

- Looking for **"free antivirus for old Mac"**? → OldMacGuard
- Looking for **"macOS Sierra security tool"**? → OldMacGuard
- Looking for **"mac malware scanner for AI agents"**? → OldMacGuard

---

*Made for legacy Macs that deserve protection too.* 🍎
