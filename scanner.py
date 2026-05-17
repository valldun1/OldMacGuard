#!/usr/bin/env python3
"""
macOS Security Scanner — High Sierra compatible
Проверка: вирусы, малварь, подозрительные процессы, автозагрузка, сеть, шифрование
Использует только built-in macOS утилиты и Python stdlib — никаких внешних зависимостей
"""

import os
import sys
import subprocess
import json
import plistlib
import pwd
import grp
import socket
import struct
import time
import re
import argparse
from datetime import datetime
from pathlib import Path

VERSION = "1.1"
REPORT = {
    "time": datetime.now().isoformat(),
    "hostname": socket.gethostname(),
    "findings": [],
    "score": 100  # стартуем отлично, минусуем за проблемы
}

# ===== ЗАГРУЗКА СИГНАТУР ИЗ ВНЕШНЕЙ БАЗЫ =====
SCRIPT_DIR = Path(__file__).parent.resolve()
SIGNATURES_PATH = SCRIPT_DIR / "malware-signatures.json"
BUILTIN_SIGNATURES_VERSION = "1.0"

def load_signatures():
    """Загрузить сигнатуры из файла. Если файла none — вернуть встроенные."""
    default = {
        "suspicious_processes": {
            "MacVxIP": "Adware/Malware",
            "Advanced Mac Cleaner": "PUP (Fake Cleaner)",
            "MacBooster": "PUP (Fake Optimizer)",
            "MacKeeper": "PUP (Fake Utility)",
            "SearchHelper": "Adware",
            "Genieo": "Adware",
            "VSearch": "Adware/Browser Hijacker",
            "Conduit": "Adware",
            "BrowseFox": "Adware",
            "Spigot": "Adware",
            "InstallCore": "PUP Installer",
            "CrossRider": "Adware",
            "OpenInstall": "PUP Installer",
            "MPlayerX": "Adware bundle",
            "MacTmp": "Adware",
            "SearchProtect": "Browser Hijacker",
            "MySearchDial": "Browser Hijacker",
            "Delta Search": "Browser Hijacker",
            "Safe Finder": "Adware/Browser Hijacker",
            "Coupon Drop": "Adware",
            "Shopping Helper": "Adware",
            "Mr. Mac Cleaner": "Fake Cleaner",
            "Expert Mac Cleaner": "Fake Cleaner",
            "Shrem": "Trojan",
            "Komodia": "Adware (redirect)",
            "WebCompanion": "Adware",
            "NicePlayer": "Adware",
            "VidStep": "Adware/Scam"
        },
        "suspicious_domains": [
            "search.genieo.com", "search.conduit.com", "delta-homes.com",
            "search.mysearchdial.com", "search.safefinder.com",
            "search.searchprotect.com", "search.tb.ask.com",
            "search.browsefox.com", "search.visymosearch.com"
        ],
        "suspicious_app_names": [
            "MPlayerX", "NicePlayer", "MacKeeper", "MacBooster",
            "Advanced Mac Cleaner", "VidStep", "MacTmp",
            "Mr. Mac Cleaner", "Expert Mac Cleaner"
        ],
        "suspicious_launchagent_keywords": [
            "genieo", "conduit", "vsearch", "searchprotect",
            "browsefox", "spigot", "installcore"
        ]
    }
    try:
        if SIGNATURES_PATH.exists():
            with open(SIGNATURES_PATH) as f:
                sigs = json.load(f)
            upd = sigs.get('updated', 'N/A') or 'N/A'
            sig_ver = sigs.get('version', '?') or '?'
            print("  [DB] Signatures v{} (from {})".format(sig_ver, upd))
            return sigs
        else:
            print(f"  📦 Using built-in signatures v{BUILTIN_SIGNATURES_VERSION}")
            return default
    except Exception as e:
        print(f"  ⚠️ Error loading signatures: {e}. Using built-in.")
        return default

SIGS = load_signatures()
SUSPICIOUS_PROCESSES = SIGS.get("suspicious_processes", {})
SUSPICIOUS_DOMAINS = SIGS.get("suspicious_domains", [])
SUSPICIOUS_APP_NAMES = SIGS.get("suspicious_app_names", [])
SUSPICIOUS_LAUNCHAGENT_KEYWORDS = SIGS.get("suspicious_launchagent_keywords", [])


def run_cmd(cmd, timeout=30):
    """Выполнить shell-команду, вернуть stdout"""
    try:
        result = subprocess.run(
            cmd, shell=True, capture_output=True, text=True, timeout=timeout
        )
        return result.stdout.strip()
    except subprocess.TimeoutExpired:
        return f"[TIMEOUT] {cmd}"
    except Exception as e:
        return f"[ERROR] {e}"

def add_finding(category, severity, title, detail, fix=""):
    """Добавить находку в отчёт"""
    sev_map = {"critical": -15, "high": -10, "medium": -5, "low": -2, "info": 0}
    REPORT["score"] += sev_map.get(severity, 0)
    REPORT["findings"].append({
        "category": category,
        "severity": severity,
        "title": title,
        "detail": detail,
        "fix": fix
    })

def format_report():
    """Форматировать отчёт в читаемый вид"""
    lines = []
    lines.append("=" * 60)
    lines.append(f"🍎 macOS Security Scan — {REPORT['hostname']}")
    lines.append(f"   Time: {REPORT['time']}")
    lines.append(f"   Security score: {max(0, REPORT['score'])}/100")
    lines.append("=" * 60)

    # Группировка по категориям
    categories = {}
    for f in REPORT["findings"]:
        cat = f["category"]
        if cat not in categories:
            categories[cat] = []
        categories[cat].append(f)

    for cat, items in categories.items():
        lines.append(f"\n📁 {cat}")
        lines.append("-" * 40)
        for item in items:
            icons = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "info": "ℹ️"}
            icon = icons.get(item["severity"], "⚪")
            lines.append(f"  {icon} [{item['severity'].upper()}] {item['title']}")
            lines.append(f"     {item['detail']}")
            if item["fix"]:
                lines.append(f"     💡 {item['fix']}")

    lines.append("\n" + "=" * 60)
    lines.append(f"📊 TOTAL: {len(REPORT['findings'])} findings | Score: {max(0, REPORT['score'])}/100")
    if REPORT["score"] >= 80:
        lines.append("✅ System is in good shape")
    elif REPORT["score"] >= 50:
        lines.append("⚠️ Room for improvement")
    else:
        lines.append("🔴 Immediate attention required!")
    lines.append("=" * 60)

    return "\n".join(lines)

# ═══════════════════════════════════════════
# 1. СИСТЕМНАЯ ИНФОРМАЦИЯ
# ═══════════════════════════════════════════

def check_system_info():
    macos = run_cmd("sw_vers -productVersion")
    build = run_cmd("sw_vers -buildVersion")
    serial = run_cmd("system_profiler SPHardwareDataType | grep Serial | awk '{print $4}'")
    ram = run_cmd("sysctl hw.memsize | awk '{print $2/1024/1024/1024 \" GB\"}'")
    cpu = run_cmd("sysctl -n machdep.cpu.brand_string")
    disk = run_cmd("df -h / | tail -1 | awk '{print $3 \" used / \" $2 \" total (\" $5 \" full)\"}'")
    uptime = run_cmd("uptime | sed 's/.*up //' | sed 's/,.*//'")

    add_finding("System", "info", f"macOS {macos} ({build})", f"CPU: {cpu}\nRAM: {ram}\nDisk: {disk}\nUptime: {uptime}\nSerial: {serial}")

    # Проверка версии — High Sierra не получает обновлений
    if "10.13" in macos:
        add_finding("System", "medium", "macOS High Sierra — no longer receiving security updates",
                    "System выпущена в 2017, Apple остановила поддержку. Рекомендуется обновление до совместимой версии.",
                    "Upgrade to macOS Catalina (10.15) or use OCLP patches for Monterey+")

# ═══════════════════════════════════════════
# 2. БАЗОВАЯ ЗАЩИТА (FileVault, SIP, Gatekeeper, Firewall)
# ═══════════════════════════════════════════

def check_basic_security():
    # FileVault
    fv = run_cmd("fdesetup status")
    if "On" in fv or "on" in fv:
        add_finding("Encryption", "info", "FileVault is ON ✅", fv)
    else:
        add_finding("Encryption", "high", "FileVault is OFF ❌",
                    fv, "Enable: System Preferences → Security → FileVault")

    # SIP
    sip = run_cmd("csrutil status")
    if "enabled" in sip.lower():
        add_finding("SIP", "info", "System Integrity Protection is ON ✅", sip)
    else:
        add_finding("SIP", "high", "SIP is OFF ❌ — system is vulnerable",
                    sip, "Enable: reboot → Cmd+R → Terminal → csrutil enable")

    # Gatekeeper
    gk = run_cmd("spctl --status")
    if "enabled" in gk.lower():
        add_finding("Gatekeeper", "info", "Gatekeeper is ON ✅", gk)
    else:
        add_finding("Gatekeeper", "high", "Gatekeeper is OFF ❌",
                    gk, "Enable: spctl --master-enable / System Preferences → Security")

    # Firewall
    fw = run_cmd("/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate")
    if "enabled" in fw.lower():
        add_finding("Firewall", "info", "Firewall is ON ✅", fw)
    else:
        add_finding("Firewall", "medium", "Firewall is OFF",
                    fw, "Enable: socketfilterfw --setglobalstate on")

    # Stealth mode
    stealth = run_cmd("/usr/libexec/ApplicationFirewall/socketfilterfw --getstealthmode")
    if "enabled" in stealth.lower():
        add_finding("Firewall", "info", "Stealth Mode is ON ✅", stealth)
    else:
        add_finding("Firewall", "low", "Stealth Mode is OFF",
                    stealth, "Enable: socketfilterfw --setstealthmode on")

# ═══════════════════════════════════════════
# 3. ПРОЦЕССЫ — поиск малвари и подозрительных
# ═══════════════════════════════════════════

def check_processes():
    all_procs = run_cmd("ps aux")
    procs_found = []

    for name, desc in SUSPICIOUS_PROCESSES.items():
        if name.lower() in all_procs.lower():
            # Найти PID
            pid_line = ""
            for line in all_procs.split('\n'):
                if name.lower() in line.lower():
                    pid_line = line.strip()
                    break

            procs_found.append((name, desc, pid_line))
            add_finding("Processes", "critical", f"⚠️ FOUND: {name} ({desc})",
                        f"PID: {pid_line.split()[1] if pid_line else 'N/A'}\n{pid_line}",
                        f"Remove: killall '{name}' && удали приложение из /Applications/")

    # Проверка на неизвестные процессы с высоким CPU
    high_cpu = run_cmd("ps aux --sort=-%cpu 2>/dev/null || ps aux -r 2>/dev/null | head -20")
    lines = high_cpu.split('\n')
    for line in lines[1:11]:  # топ-10 по CPU
        parts = line.split()
        if len(parts) > 10:
            try:
                cpu = float(parts[2])
                name = parts[10] if len(parts) > 10 else parts[-1]
                if cpu > 50 and not any(x in name for x in ['kernel', 'WindowServer', 'Chrome', 'Hermes', 'Google Chrome']):
                    add_finding("Processes", "low", f"High CPU load: {name} ({cpu}%)",
                                line, "Check what this process is")
            except (ValueError, IndexError):
                pass

    if not procs_found:
        add_finding("Processes", "info", "No suspicious processes found ✅",
                    f"Total processes: {run_cmd('ps aux | wc -l').strip()}")

# ═══════════════════════════════════════════
# 4. АВТОЗАГРУЗКА — LaunchAgents, Daemons, Login Items
# ═══════════════════════════════════════════

def check_launch_agents():
    # User LaunchAgents
    user_la = list(Path.home().glob("Library/LaunchAgents/*.plist"))
    reported = []
    for plist in user_la:
        name = plist.name
        try:
            with open(plist, 'rb') as f:
                data = plistlib.load(f)
            prog = data.get('Program', data.get('ProgramArguments', ['']))[0] if isinstance(data.get('ProgramArguments'), list) else str(data.get('Program', ''))
            reported.append(f"  • {name} → {prog}")
        except:
            reported.append(f"  • {name} → (failed to read)")

    # System LaunchDaemons (только сторонние)
    sys_ld = list(Path("/Library/LaunchDaemons").glob("*.plist")) if os.path.isdir("/Library/LaunchDaemons") else []
    third_party_ld = []
    for plist in sys_ld:
        if plist.name.startswith('com.apple.') or plist.name.startswith('com.openssh.'):
            continue
        try:
            with open(plist, 'rb') as f:
                data = plistlib.load(f)
            prog = str(data.get('Program', data.get('ProgramArguments', [''])))[:120]
            third_party_ld.append(f"  • {plist.name} → {prog}")
        except:
            third_party_ld.append(f"  • {plist.name} → (failed to read)")

    add_finding("Startup", "info", f"User LaunchAgents: {len(user_la)}",
                '\n'.join(reported) if reported else "Empty (only Hermes)")

    if third_party_ld:
        add_finding("Startup", "info", f"Third-party System LaunchDaemons: {len(third_party_ld)}",
                    '\n'.join(third_party_ld))
    else:
        add_finding("Startup", "info", "No third-party System LaunchDaemons ✅")

    # Login Items
    login_items = run_cmd("osascript -e 'tell app \"System Events\" to get name of every login item' 2>/dev/null")
    add_finding("Startup", "info", f"Login Items: {login_items if login_items else 'none'}",
                f"Starting at login: {login_items}")

# ═══════════════════════════════════════════
# 5. ПЛАНИРОВЩИК (cron, at)
# ═══════════════════════════════════════════

def check_scheduler():
    # Cron jobs
    cron = run_cmd("crontab -l 2>/dev/null || echo 'No cron'")
    if "Нет cron" in cron or not cron.strip():
        add_finding("Scheduler", "info", "No user cron jobs ✅", "crontab -l: empty")
    else:
        add_finding("Scheduler", "medium", "Found cron jobs — review them",
                    cron[:500], "Verify each job is safe: crontab -l")

    # System cron (справочно)
    system_cron = run_cmd("ls /etc/periodic/daily/ /etc/periodic/weekly/ /etc/periodic/monthly/ 2>/dev/null")

# ═══════════════════════════════════════════
# 6. СЕТЬ — открытые порты, подозрительные соединения
# ═══════════════════════════════════════════

def check_network():
    # Listening ports
    listening = run_cmd("lsof -iTCP -sTCP:LISTEN -P -n 2>/dev/null || netstat -an -p tcp | grep LISTEN")
    add_finding("Network", "info", "Open TCP ports (listening):",
                listening[:500] if len(listening) > 500 else listening,
                "Verify all ports are expected services")

    # Check for SSH
    ssh_enabled = run_cmd("systemsetup -getremotelogin 2>/dev/null")
    if "On" in ssh_enabled:
        # Check SSH config
        ssh_permit_root = run_cmd("grep -i 'PermitRootLogin' /etc/ssh/sshd_config 2>/dev/null | grep -v '#'")
        ssh_pass = run_cmd("grep -i 'PasswordAuthentication' /etc/ssh/sshd_config 2>/dev/null")
        add_finding("Network", "medium", "SSH (Remote Login) is ON",
                    f"{ssh_enabled}\n{ssh_permit_root}\n{ssh_pass}",
                    "Ensure PasswordAuthentication no, PermitRootLogin no")

    # Проверка DNS на подозрительные домены (обычно adware меняет DNS)
    try:
        for domain in SUSPICIOUS_DOMAINS:
            try:
                ip = socket.gethostbyname(domain)
                add_finding("Network", "high", f"⚠️ Suspicious domain resolves: {domain} → {ip}",
                            "This domain may be linked to adware/hijacker",
                            "Check DNS settings: networksetup -getdnsservers Wi-Fi")
                break
            except socket.gaierror:
                pass
    except:
        pass

# ═══════════════════════════════════════════
# 7. БРАУЗЕРНЫЕ РАСШИРЕНИЯ (Chrome/Safari)
# ═══════════════════════════════════════════

def check_browser():
    # Safari extensions
    safari_ext = run_cmd("find ~/Library/Safari/Extensions -name '*.safariextz' -o -name '*.safariextension' 2>/dev/null | head -20")
    if safari_ext:
        add_finding("Browser", "medium", f"Safari extensions ({len(safari_ext.splitlines())}):",
                    safari_ext[:300])

    # Chrome extensions — ищем manifest.json внутри папки с версией
    chrome_ext_path = Path.home() / "Library/Application Support/Google/Chrome/Default/Extensions"
    if chrome_ext_path.exists():
        chrome_exts = list(chrome_ext_path.glob("*"))
        if chrome_exts:
            ext_info = []
            for ext in chrome_exts:
                # Структура: ext_id/VERSION/manifest.json
                versions = list(ext.glob("*"))
                if not versions:
                    continue
                # Берём последнюю версию
                latest = sorted(versions)[-1]
                manifest = latest / "manifest.json"
                if manifest.exists():
                    try:
                        with open(manifest) as f:
                            data = json.load(f)
                        name = data.get("name", "unknown")
                        ext_info.append(f"  • {ext.name}: {name} (v{latest.name})")
                    except:
                        ext_info.append(f"  • {ext.name}: (failed to read)")
            add_finding("Browser", "info", f"Chrome extensions ({len(chrome_exts)}):",
                        '\n'.join(ext_info) if ext_info else "Has extensions")

# ═══════════════════════════════════════════
# 8. ПРОВЕРКА ЗЛОКАЧЕСТВЕННЫХ ПАКЕТОВ В /Applications
# ═══════════════════════════════════════════

def check_applications():
    # Подозрительные приложения
    apps = run_cmd("ls /Applications/")
    susp_apps = []
    for name, desc in SUSPICIOUS_PROCESSES.items():
        if name.lower() in apps.lower():
            susp_apps.append(f"{name} ({desc})")

    if susp_apps:
        for sa in susp_apps:
            add_finding("Applications", "critical", f"⚠️ Suspicious app: {sa}",
                        "Found in /Applications/",
                        f"Remove: sudo rm -rf '/Applications/{sa.split(' (')[0]}'")
    else:
        add_finding("Applications", "info", "No suspicious applications found ✅",
                    f"Total in /Applications/: {len(apps.splitlines())} apps")

    # Проверка SETUID битов
    # suid = run_cmd("find / -perm -4000 -type f 2>/dev/null | head -20")
    # add_finding("Applications", "info", "SUID бинарники:", suid[:500])

# ═══════════════════════════════════════════
# 9. СЕТЕВЫЕ ФИЛЬТРЫ И VPN (защита)
# ═══════════════════════════════════════════

def check_network_protection():
    # ZeroTier status
    zt = run_cmd("ps aux | grep -i zerotier | grep -v grep | head -5")
    if zt:
        zt_networks = run_cmd("zerotier-cli listnetworks 2>/dev/null | grep OK || echo 'Failed'")
        add_finding("Network", "info", f"ZeroTier: active", zt_networks if zt_networks != 'Failed' else "Running")

    # VPN check
    vpn = run_cmd("scutil --nc list 2>/dev/null | head -10")
    if vpn:
        add_finding("Network", "info", "VPN connections:", vpn)

    # DNS configuration
    dns = run_cmd("networksetup -getdnsservers Wi-Fi 2>/dev/null || networksetup -getdnsservers Ethernet 2>/dev/null")
    if dns and dns != "(null)":
        add_finding("Network", "info", f"DNS servers: {dns}", "Verify these are your DNS servers")

# ═══════════════════════════════════════════
# 10. ПАМЯТЬ И ДИСК
# ═══════════════════════════════════════════

def check_resources():
    # Memory
    mem = run_cmd("sysctl hw.memsize | awk '{print $2/1024/1024/1024 \" GB\"}'")
    swap = run_cmd("sysctl vm.swapusage | awk '{print $1, $2, $3, $4, $5}'")
    load = run_cmd("uptime | awk -F'load averages:' '{print $2}'")

    # Disk
    disk_usage = run_cmd("df -h / | tail -1")
    disk_pct = disk_usage.split()[-2].replace('%', '') if disk_usage else '0'
    try:
        if int(disk_pct) > 90:
            add_finding("Resources", "medium", f"Disk is {disk_pct}% full ❌",
                        disk_usage, "Free up space: clear caches, remove unused files")
        elif int(disk_pct) > 80:
            add_finding("Resources", "low", f"Disk is {disk_pct}% full ⚠️",
                        disk_usage, "Recommended to free up space")
    except:
        pass

    add_finding("Resources", "info", f"RAM: {mem.strip()} | Swap: {swap.strip()}",
                f"Load Average: {load.strip()}")

# ═══════════════════════════════════════════
# 11. ПОСЛЕДНИЕ НЕУДАЧНЫЕ ВХОДЫ (брутфорс?)
# ═══════════════════════════════════════════

def check_auth_log():
    last_failed = run_cmd("log show --predicate 'process contains \"sshd\" and message contains \"Failed\"' --last 1d 2>/dev/null | tail -5")
    if not last_failed:
        last_failed = run_cmd("last -10 2>/dev/null")
    add_finding("Authentication", "info", "Last logins:", last_failed[:500] if last_failed else "No data")

# ═══════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════

def main(report_path=None):
    print("🔍 macOS Security Scanner v" + VERSION)
    print("  Scanning system...\n")

    check_system_info()
    check_basic_security()
    check_processes()
    check_launch_agents()
    check_scheduler()
    check_applications()
    check_network()
    check_network_protection()
    check_browser()
    check_resources()
    check_auth_log()

    report = format_report()

    if report_path:
        # JSON output for AI agents / programmatic consumption
        json_report = {
            "version": VERSION,
            "time": REPORT["time"],
            "hostname": REPORT["hostname"],
            "score": max(0, REPORT["score"]),
            "findings": REPORT["findings"],
            "summary": "good" if REPORT["score"] >= 80 else ("warning" if REPORT["score"] >= 50 else "critical"),
            "total_findings": len(REPORT["findings"]),
        }
        report_path = Path(report_path)
        report_path.parent.mkdir(parents=True, exist_ok=True)
        with open(report_path, 'w') as f:
            json.dump(json_report, f, indent=2, ensure_ascii=False)
        print(f"\n📊 JSON report saved: {report_path}")
    else:
        print(report)

    # Save text report next to script
    report_dir = SCRIPT_DIR / "reports"
    report_dir.mkdir(parents=True, exist_ok=True)
    report_path_txt = report_dir / f"security-scan-{datetime.now().strftime('%Y%m%d-%H%M%S')}.txt"
    with open(report_path_txt, 'w') as f:
        f.write(report)
    print(f"📝 Report saved: {report_path_txt}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="OldMacGuard — macOS Security Scanner for legacy Macs")
    parser.add_argument("--report", type=str, default=None,
                        help="Save machine-readable JSON report to PATH (e.g. /tmp/security.json)")
    args = parser.parse_args()
    main(report_path=args.report)