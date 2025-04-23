# Define the share path. Note the use of single quotes and a doubled trailing backslash to ensure the literal backslash is preserved.
$share_path = '\\tsclient\mona-share\\'
$install_dir = "C:\Users\Administrator\Desktop\install-mona"

echo "[+] Creating installation directory: $install_dir"
mkdir "$install_dir"

# Ensure Windows Modules Installer (TrustedInstaller) is enabled and running.
echo "[+] Ensuring Windows Modules Installer (TrustedInstaller) is enabled"
Try {
    Set-Service -Name TrustedInstaller -StartupType Manual -ErrorAction Stop
    Start-Service -Name TrustedInstaller -ErrorAction Stop
    echo "[+] Windows Modules Installer started successfully."
}
Catch {
    Write-Error "[-] Failed to start Windows Modules Installer: $_"
}

# Copy the WinDBG theme to the install dir
echo "[+] Copying the Windbg workspace file"
copy "$share_path\dark.wew" "$install_dir"
copy "$share_path\windbg_dark.bat" "$install_dir"
Start-Sleep -Seconds 5

# Install old C++ runtime
echo "[+] Installing old C++ runtime"
copy "$share_path\vcredist_x86.exe" "$install_dir"
cd "$install_dir"
.\vcredist_x86.exe 
Start-Sleep -Seconds 60

echo "[+] Backing up old pykd files"
move "C:\Program Files (x86)\Windows Kits\10\Debuggers\x86\winext\pykd.pyd" "C:\Program Files (x86)\Windows Kits\10\Debuggers\x86\winext\pykd.pyd.bak"
move "C:\Program Files (x86)\Windows Kits\10\Debuggers\x86\winext\pykd.dll" "C:\Program Files (x86)\Windows Kits\10\Debuggers\x86\winext\pykd.dll.bak"

# Install Python2.7
echo "[+] Installing Python2.7"
copy "$share_path\python-2.7.17.msi" "$install_dir"
msiexec.exe /i "$install_dir\python-2.7.17.msi" /qn
Start-Sleep -Seconds 10

# Register Python2.7 binaries in the PATH (before Python3)
echo "[+] Adding Python2.7 to the PATH"
$p = [System.Environment]::GetEnvironmentVariable('Path', [System.EnvironmentVariableTarget]::User)
[System.Environment]::SetEnvironmentVariable('Path', "C:\Python27\;C:\Python27\Scripts;" + $p, [System.EnvironmentVariableTarget]::User)

# Copy mona files and fresh pykd
echo "[+] Bringing over mona files and fresh pykd"
copy "$share_path\windbglib.py" "C:\Program Files (x86)\Windows Kits\10\Debuggers\x86"
copy "$share_path\mona.py" "C:\Program Files (x86)\Windows Kits\10\Debuggers\x86"
copy "$share_path\pykd.pyd" "C:\Program Files (x86)\Windows Kits\10\Debuggers\x86\winext"

# Register the runtime debug DLL
echo "[+] Registering runtime debug DLL"
cd "C:\Program Files (x86)\Common Files\Microsoft Shared\VC"
regsvr32 /s msdia90.dll

echo "[=] In case you see something about symbols when running mona, try executing the following (the runtime took too long to install):"
echo 'regsvr32 "C:\Program Files\Common Files\Microsoft Shared\VC\msdia90.dll"'
