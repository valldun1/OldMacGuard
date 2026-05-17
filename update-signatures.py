#!/usr/bin/env python3
"""
macOS Malware Signature Updater — обновляет базу угроз из публичных источников
Запускать раз в месяц для поддержания актуальности.
"""

import json
import subprocess
import sys
import os
from datetime import datetime
from pathlib import Path

SIGNATURES_PATH = Path.home() / ".hermes" / "scripts" / "malware-signatures.json"

def curl(url, timeout=15):
    """Получить текст URL через curl"""
    try:
        r = subprocess.run(
            ["curl", "-sL", "--max-time", str(timeout), url],
            capture_output=True, text=True
        )
        if r.returncode == 0 and r.stdout.strip():
            return r.stdout.strip()
    except Exception as e:
        print(f"  ⚠️ curl failed: {e}")
    return ""

def fetch_malware_names():
    """Собрать названия малвари из публичных источников"""
    new_names = {}
    
    # 1. Objective-See Mac Malware list (github)
    print("  [1/4] Objective-See malware list...")
    data = curl("https://raw.githubusercontent.com/objective-see/Malware/main/Malware.plist")
    if data:
        # Simple parsing - extract malware names
        for line in data.split('\n'):
            line = line.strip()
            if '<string>' in line:
                name = line.replace('<string>', '').replace('</string>', '').strip()
                if name and len(name) > 2 and not name.startswith('com.') and not name.startswith('http'):
                    new_names[name] = "Mac Malware (Objective-See)"

    # 2. MacAdware.org known threats
    print("  [2/4] MacAdware list...")
    data = curl("https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/BaseFilter/sections/adware.txt")
    if data:
        for line in data.split('\n'):
            if '||' in line and '.com^' in line:
                domain = line.split('||')[1].split('^')[0]
                if domain.count('.') <= 3:  # reasonable domain
                    new_names[domain] = "Adware Domain"

    # 3. Known Mac malware family names (hardcoded broad list)
    additional_malware = {
        "Bundlore": "Mac Adware (Bundlore family)",
        "Shlayer": "Mac Trojan (Shlayer)",
        "Pirrit": "Mac Adware (Pirrit)",
        "MaxOffer": "Mac Adware (MaxOfferDeal)",
        "SearchAwesome": "Mac Adware/Browser Hijacker",
        "NewTab": "Mac Adware (NewTab)",
        "InstallCore": "PUP Installer",
        "Mughthesec": "Mac Adware",
        "Moliug": "Mac Adware",
        "AdvancedCleaner": "Fake Mac Cleaner",
        "FkInstall": "Mac Adware",
        "FkMacVx": "Mac Adware",
        "Genieo": "Mac Adware",
        "Conduit": "Adware/Toolbar",
        "Mobogenie": "PUP",
        "Spigot": "Adware",
        "VSearch": "Adware/Hijacker",
        "BrowseFox": "Adware",
        "CrossRider": "Adware",
        "OpenInstall": "PUP",
        "SearchHelper": "Adware",
        "SearchProtect": "Browser Hijacker",
        "MySearchDial": "Browser Hijacker",
        "Delta Search": "Browser Hijacker",
        "Safe Finder": "Adware/Hijacker",
        "PremierOpinion": "Spyware",
        "Tuguu": "Mac Adware",
        "Mackeeper": "PUP (Fake Utility)",
        "MacBooster": "PUP (Fake Optimizer)",
        "Wajam": "Adware",
        "Linkury": "Adware",
        "EliteSearch": "Adware",
        "CouponDrop": "Adware",
        "ShoppingHelper": "Adware"
    }
    
    print("  [3/4] Additional known malware...")
    for name, desc in additional_malware.items():
        new_names[name] = desc
    
    # 4. Check Apple's XProtect (built-in Mac antivirus)
    print("  [4/4] Apple XProtect signatures...")
    xprotect_paths = [
        "/System/Library/CoreServices/XProtect.bundle/Contents/Resources/XProtect.plist",
        "/Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Resources/XProtect.plist"
    ]
    for xp in xprotect_paths:
        xp_file = Path(xp)
        if xp_file.exists():
            try:
                import plistlib
                with open(xp_file, 'rb') as f:
                    xp_data = plistlib.load(f)
                if isinstance(xp_data, dict):
                    items = xp_data.get('Extensions', xp_data.get('PlugIns', xp_data.get('items', [])))
                    if isinstance(items, list):
                        for item in items:
                            if isinstance(item, dict):
                                name = item.get('name', item.get('identifier', ''))
                                if name:
                                    new_names[name] = f"Mac Malware (XProtect: {item.get('version', '?')})"
            except Exception as e:
                print(f"  ⚠️ XProtect parse error: {e}")
    
    return new_names

def update_signatures(new_names):
    """Добавить новые имена в существующую базу сигнатур"""
    if not SIGNATURES_PATH.exists():
        print("  ❌ Signatures file not found!")
        return False
    
    with open(SIGNATURES_PATH) as f:
        sigs = json.load(f)
    
    existing = sigs.get("suspicious_processes", {})
    old_count = len(existing)
    added = 0
    
    for name, desc in sorted(new_names.items()):
        if name not in existing:
            # Skip short names or generic words
            if len(name) < 3:
                continue
            existing[name] = desc
            added += 1
    
    sigs["suspicious_processes"] = existing
    sigs["version"] = str(float(sigs.get("version", "1.0")) + 0.1)
    sigs["updated"] = datetime.now().strftime("%Y-%m-%d")
    
    with open(SIGNATURES_PATH, 'w') as f:
        json.dump(sigs, f, indent=2, ensure_ascii=False)
    
    print(f"\n  📊 Было: {old_count} сигнатур")
    print(f"  ➕ Добавлено: {added} новых")
    print(f"  📦 Всего: {len(existing)} сигнатур")
    print(f"  🆕 Версия: {sigs['version']}")
    return True

def main():
    print("=" * 50)
    print("🧬 macOS Malware Signature Updater")
    print(f"   {datetime.now().strftime('%Y-%m-%d %H:%M')}")
    print("=" * 50)
    
    print("\n📡 Fetching malware intelligence...")
    new_names = fetch_malware_names()
    
    print(f"\n📥 Raw names collected: {len(new_names)}")
    
    print("\n💾 Updating signatures database...")
    if update_signatures(new_names):
        print("\n✅ Signatures updated successfully!")
    else:
        print("\n❌ Update failed!")

if __name__ == "__main__":
    main()
