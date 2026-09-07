#!/usr/bin/env python3
import sys
import re

def parse_templates():
    data = sys.stdin.read()
    hits = []

    # Split by LDAP entry blocks
    blocks = data.split("\n\n")
    for block in blocks:
        name_m = re.search(r"(?:name|cn):\s*(.+)", block, re.IGNORECASE)
        flag_m = re.search(r"msPKI-Certificate-Name-Flag:\s*(-?\d+)", block, re.IGNORECASE)

        if name_m and flag_m:
            name = name_m.group(1).strip()
            raw_val = int(flag_m.group(1))
            # Convert signed 32-bit integer to unsigned hex representation
            unsigned_val = raw_val & 0xFFFFFFFF
            hex_str = f"0x{unsigned_val:08x}"

            # Check for Enrollee Supplies Subject flag (0x1) or custom combinations
            is_abusable = bool(unsigned_val & 0x1)
            status = "[!] ESC1 VULN" if is_abusable else "[+] Secure"

            hits.append({
                "name": name,
                "raw": raw_val,
                "hex": hex_str,
                "status": status
            })

    if not hits:
        print("[-] No template name flags found in input.")
        return

    print(f"{'Template Name':<30} | {'Decimal Value':<15} | {'Hex Bitmask':<12} | {'Status':<15}")
    print("-" * 80)
    for h in hits:
        print(f"{h['name']:<30} | {str(h['raw']):<15} | {h['hex']:<12} | {h['status']:<15}")

if __name__ == "__main__":
    parse_templates()
