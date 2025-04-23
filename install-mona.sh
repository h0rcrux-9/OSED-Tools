#!/bin/bash

# Start Updog in the background on port 8080
echo "[*] Starting Updog..."
python3 -m updog &
UPDOG_PID=$!
echo "[+] Updog started with PID $UPDOG_PID"

TOOLS=("https://github.com/corelan/windbglib/raw/master/pykd/pykd.zip" "https://github.com/corelan/windbglib/raw/master/windbglib.py" "https://github.com/corelan/mona/raw/master/mona.py" "https://www.python.org/ftp/python/2.7.17/python-2.7.17.msi" "https://download.microsoft.com/download/2/E/6/2E61CFA4-993B-4DD4-91DA-3737CD5CD6E3/vcredist_x86.exe" "http://localhost:9090/install-mona.ps1" "https://github.com/lololosys/windbg-theme/raw/refs/heads/master/dark.wew")

TMPDIR=$(mktemp -d)
SHARENAME="mona-share"
SHARE="\\\\tsclient\\$SHARENAME"

trap "rm -rf $TMPDIR" SIGINT 

pushd $TMPDIR >/dev/null

echo "[+] once the RDP window opens, execute the following command in an Administrator terminal:"
echo
echo "powershell -c \"cat $SHARE\\install-mona.ps1 | powershell -\""
echo

for tool in "${TOOLS[@]}"; do
    echo "[=] downloading $tool"
    wget -q "$tool"
done

unzip -qqo pykd.zip

# Kill Updog
echo "[*] Killing Updog..."
kill "$UPDOG_PID"
wait "$UPDOG_PID" 2>/dev/null

rdesktop ${1} -u Administrator -p lab -r disk:$SHARENAME=.
