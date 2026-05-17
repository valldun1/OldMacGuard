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
    """Загрузить сигнатуры из файла. Если файла нет — вернуть встроенные."""
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
            print(f"  📦 Используются встроенные сигнатуры v{BUILTIN_SIGNATURES_VERSION}")
            return default
    except Exception as e:
        print(f"  ⚠️ Ошибка загрузки сигнатур: {e}. Использую встроенные.")
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
    lines.append(f"   Время: {REPORT['time']}")
    lines.append(f"   Оценка безопасности: {max(0, REPORT['score'])}/100")
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
    lines.append(f"📊 ИТОГО: {len(REPORT['findings'])} находок | Оценка: {max(0, REPORT['score'])}/100")
    if REPORT["score"] >= 80:
        lines.append("✅ Система в хорошем состоянии")
    elif REPORT["score"] >= 50:
        lines.append("⚠️ Есть что улучшить")
    else:
        lines.append("🔴 Требуется немедленное внимание!")
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

    add_finding("Система", "info", f"macOS {macos} ({build})", f"CPU: {cpu}\nRAM: {ram}\nДиск: {disk}\nUptime: {uptime}\nSerial: {serial}")

    # Проверка версии — High Sierra не получает обновлений
    if "10.13" in macos:
        add_finding("Система", "medium", "macOS High Sierra — больше не получает обновлений безопасности",
                    "Система выпущена в 2017, Apple остановила поддержку. Рекомендуется обновление до совместимой версии.",
                    "Обновиться до macOS Catalina (10.15) или установить патчи OCLP для Monterey+")

# ═══════════════════════════════════════════
# 2. БАЗОВАЯ ЗАЩИТА (FileVault, SIP, Gatekeeper, Firewall)
# ═══════════════════════════════════════════

def check_basic_security():
    # FileVault
    fv = run_cmd("fdesetup status")
    if "On" in fv or "on" in fv:
        add_finding("Шифрование", "info", "FileVault включён ✅", fv)
    else:
        add_finding("Шифрование", "high", "FileVault НЕ включён ❌",
                    fv, "Включи: System Preferences → Security → FileVault")

    # SIP
    sip = run_cmd("csrutil status")
    if "enabled" in sip.lower():
        add_finding("SIP", "info", "System Integrity Protection включён ✅", sip)
    else:
        add_finding("SIP", "high", "SIP отключён ❌ — система уязвима",
                    sip, "Включи: reboot → Cmd+R → Terminal → csrutil enable")

    # Gatekeeper
    gk = run_cmd("spctl --status")
    if "enabled" in gk.lower():
        add_finding("Gatekeeper", "info", "Gatekeeper включён ✅", gk)
    else:
        add_finding("Gatekeeper", "high", "Gatekeeper отключён ❌",
                    gk, "Включи: spctl --master-enable / System Preferences → Security")

    # Firewall
    fw = run_cmd("/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate")
    if "enabled" in fw.lower():
        add_finding("Файрволл", "info", "Файрволл включён ✅", fw)
    else:
        add_finding("Файрволл", "medium", "Файрволл НЕ включён",
                    fw, "Включи: /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on")

    # Stealth mode
    stealth = run_cmd("/usr/libexec/ApplicationFirewall/socketfilterfw --getstealthmode")
    if "enabled" in stealth.lower():
        add_finding("Файрволл", "info", "Stealth Mode включён ✅", stealth)
    else:
        add_finding("Файрволл", "low", "Stealth Mode выключен",
                    stealth, "Включи: socketfilterfw --setstealthmode on")

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
            add_finding("Процессы", "critical", f"⚠️ НАЙДЕН: {name} ({desc})",
                        f"PID: {pid_line.split()[1] if pid_line else 'N/A'}\n{pid_line}",
                        f"Удали: killall '{name}' && удали приложение из /Applications/")

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
                    add_finding("Процессы", "low", f"Высокая нагрузка CPU: {name} ({cpu}%)",
                                line, "Проверь, что это за процесс")
            except (ValueError, IndexError):
                pass

    if not procs_found:
        add_finding("Процессы", "info", "Подозрительных процессов не найдено ✅",
                    f"Всего процессов: {run_cmd('ps aux | wc -l').strip()}")

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
            reported.append(f"  • {name} → (не удалось прочитать)")

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
            third_party_ld.append(f"  • {plist.name} → (не удалось прочитать)")

    add_finding("Автозагрузка", "info", f"User LaunchAgents: {len(user_la)} шт.",
                '\n'.join(reported) if reported else "Пусто (только Hermes)")

    if third_party_ld:
        add_finding("Автозагрузка", "info", f"Сторонние System LaunchDaemons: {len(third_party_ld)} шт.",
                    '\n'.join(third_party_ld))
    else:
        add_finding("Автозагрузка", "info", "Сторонних System LaunchDaemons нет ✅")

    # Login Items
    login_items = run_cmd("osascript -e 'tell app \"System Events\" to get name of every login item' 2>/dev/null")
    add_finding("Автозагрузка", "info", f"Login Items: {login_items if login_items else 'нет'}",
                f"При старте запускаются: {login_items}")

# ═══════════════════════════════════════════
# 5. ПЛАНИРОВЩИК (cron, at)
# ═══════════════════════════════════════════

def check_scheduler():
    # Cron jobs
    cron = run_cmd("crontab -l 2>/dev/null || echo 'Нет cron'")
    if "Нет cron" in cron or not cron.strip():
        add_finding("Планировщик", "info", "Пользовательских cron-задач нет ✅", "crontab -l: пусто")
    else:
        add_finding("Планировщик", "medium", "Найдены cron-задачи — проверь",
                    cron[:500], "Проверь что каждая задача безопасна: crontab -l")

    # System cron (справочно)
    system_cron = run_cmd("ls /etc/periodic/daily/ /etc/periodic/weekly/ /etc/periodic/monthly/ 2>/dev/null")

# ═══════════════════════════════════════════
# 6. СЕТЬ — открытые порты, подозрительные соединения
# ═══════════════════════════════════════════

def check_network():
    # Listening ports
    listening = run_cmd("lsof -iTCP -sTCP:LISTEN -P -n 2>/dev/null || netstat -an -p tcp | grep LISTEN")
    add_finding("Сеть", "info", "Открытые TCP порты (слушающие):",
                listening[:500] if len(listening) > 500 else listening,
                "Проверь что все порты — ожидаемые сервисы")

    # Check for SSH
    ssh_enabled = run_cmd("systemsetup -getremotelogin 2>/dev/null")
    if "On" in ssh_enabled:
        # Check SSH config
        ssh_permit_root = run_cmd("grep -i 'PermitRootLogin' /etc/ssh/sshd_config 2>/dev/null | grep -v '#'")
        ssh_pass = run_cmd("grep -i 'PasswordAuthentication' /etc/ssh/sshd_config 2>/dev/null")
        add_finding("Сеть", "medium", "SSH (Remote Login) включён",
                    f"{ssh_enabled}\n{ssh_permit_root}\n{ssh_pass}",
                    "Убедись что PasswordAuthentication no, PermitRootLogin no")

    # Проверка DNS на подозрительные домены (обычно adware меняет DNS)
    try:
        for domain in SUSPICIOUS_DOMAINS:
            try:
                ip = socket.gethostbyname(domain)
                add_finding("Сеть", "high", f"⚠️ Подозрительный домен резолвится: {domain} → {ip}",
                            "Этот домен может быть связан с adware/hijacker",
                            "Проверь DNS-настройки: networksetup -getdnsservers Wi-Fi")
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
        add_finding("Браузер", "medium", f"Расширения Safari ({len(safari_ext.splitlines())}):",
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
                        ext_info.append(f"  • {ext.name}: (не удалось прочитать)")
            add_finding("Браузер", "info", f"Расширения Chrome ({len(chrome_exts)} шт.):",
                        '\n'.join(ext_info) if ext_info else "Есть расширения")

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
            add_finding("Приложения", "critical", f"⚠️ Подозрительное приложение: {sa}",
                        "Обнаружено в /Applications/",
                        f"Удали: sudo rm -rf '/Applications/{sa.split(' (')[0]}'")
    else:
        add_finding("Приложения", "info", "Подозрительных приложений не найдено ✅",
                    f"Всего в /Applications/: {len(apps.splitlines())} программ")

    # Проверка SETUID битов
    # suid = run_cmd("find / -perm -4000 -type f 2>/dev/null | head -20")
    # add_finding("Приложения", "info", "SUID бинарники:", suid[:500])

# ═══════════════════════════════════════════
# 9. СЕТЕВЫЕ ФИЛЬТРЫ И VPN (защита)
# ═══════════════════════════════════════════

def check_network_protection():
    # ZeroTier status
    zt = run_cmd("ps aux | grep -i zerotier | grep -v grep | head -5")
    if zt:
        zt_networks = run_cmd("zerotier-cli listnetworks 2>/dev/null | grep OK || echo 'Не удалось'")
        add_finding("Сеть", "info", f"ZeroTier: активен", zt_networks if zt_networks != 'Не удалось' else "Запущен")

    # VPN check
    vpn = run_cmd("scutil --nc list 2>/dev/null | head -10")
    if vpn:
        add_finding("Сеть", "info", "VPN-подключения:", vpn)

    # DNS configuration
    dns = run_cmd("networksetup -getdnsservers Wi-Fi 2>/dev/null || networksetup -getdnsservers Ethernet 2>/dev/null")
    if dns and dns != "(null)":
        add_finding("Сеть", "info", f"DNS серверы: {dns}", "Проверь что это твои DNS")

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
            add_finding("Ресурсы", "medium", f"Диск заполнен на {disk_pct}% ❌",
                        disk_usage, "Освободи место: очисти кэши, удали ненужные файлы")
        elif int(disk_pct) > 80:
            add_finding("Ресурсы", "low", f"Диск заполнен на {disk_pct}% ⚠️",
                        disk_usage, "Рекомендуется освободить место")
    except:
        pass

    add_finding("Ресурсы", "info", f"RAM: {mem.strip()} | Swap: {swap.strip()}",
                f"Load Average: {load.strip()}")

# ═══════════════════════════════════════════
# 11. ПОСЛЕДНИЕ НЕУДАЧНЫЕ ВХОДЫ (брутфорс?)
# ═══════════════════════════════════════════

def check_auth_log():
    last_failed = run_cmd("log show --predicate 'process contains \"sshd\" and message contains \"Failed\"' --last 1d 2>/dev/null | tail -5")
    if not last_failed:
        last_failed = run_cmd("last -10 2>/dev/null")
    add_finding("Аутентификация", "info", "Последние логины:", last_failed[:500] if last_failed else "Нет данных")

# ═══════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════

def main(report_path=None):
    print("🔍 macOS Security Scanner v" + VERSION)
    print("  Сканирую систему...\n")

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
        print(f"\n📊 JSON-отчёт сохранён: {report_path}")
    else:
        print(report)

    # Save text report next to script
    report_dir = SCRIPT_DIR / "reports"
    report_dir.mkdir(parents=True, exist_ok=True)
    report_path_txt = report_dir / f"security-scan-{datetime.now().strftime('%Y%m%d-%H%M%S')}.txt"
    with open(report_path_txt, 'w') as f:
        f.write(report)
    print(f"📝 Отчёт сохранён: {report_path_txt}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="OldMacGuard — macOS Security Scanner for legacy Macs")
    parser.add_argument("--report", type=str, default=None,
                        help="Save machine-readable JSON report to PATH (e.g. /tmp/security.json)")
    args = parser.parse_args()
    main(report_path=args.report)
