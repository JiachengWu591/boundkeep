"""M0a E21 的本地探针（只读）：Documents 重定向、卷类型、Git Bash 路径映射、8.3 短名在不存在路径上的行为。

用法：python experiments/probe_paths_windows.py
"""
import ctypes
import json
import os
import subprocess
import sys

res = {}


def ps(cmd):
    p = subprocess.run(["powershell", "-NoProfile", "-Command", cmd], capture_output=True)
    return p.stdout.decode("utf-8", "replace").strip()


# Documents / $PROFILE 是否被 OneDrive 重定向
docs = ps("[Environment]::GetFolderPath('MyDocuments')")
prof = ps("$PROFILE.AllUsersAllHosts, $PROFILE.CurrentUserAllHosts, $PROFILE.CurrentUserCurrentHost -join '|'")
home = os.path.expanduser("~")
res["documents_folder"] = docs.replace(home, "~")
res["documents_redirected_to_onedrive"] = "onedrive" in docs.lower()
res["profile_paths"] = [p.replace(home, "~") for p in prof.split("|")]
res["home_has_non_ascii"] = any(ord(c) > 127 for c in home)

# 各盘符的文件系统（项目所在盘、用户目录所在盘）
vols = ps("Get-Volume | Where-Object DriveLetter | ForEach-Object { '{0}:{1}:{2}' -f $_.DriveLetter,$_.FileSystemType,$_.DriveType } ")
res["volumes (letter:fs:type)"] = vols.split()

# 目录级大小写敏感（WSL 创建的目录可能开启）
res["fsutil_case_sensitive_E_bk_lab"] = ps("fsutil file queryCaseSensitiveInfo E:\\bk-lab 2>&1 | Select-Object -First 2") if os.path.exists("E:\\bk-lab") else "skipped"
res["fsutil_8dot3_C"] = ps("fsutil 8dot3name query C: 2>&1 | Select-Object -First 3")

# 8.3 短名在存在 / 不存在路径上的 realpath
res["realpath existing short  C:\\PROGRA~1"] = os.path.realpath("C:\\PROGRA~1")
res["realpath nonexisting tail C:\\PROGRA~1\\nonexist"] = os.path.realpath("C:\\PROGRA~1\\nonexist")
res["realpath nonexisting short C:\\Users\\NONEXI~1"] = os.path.realpath("C:\\Users\\NONEXI~1")
res["realpath nonexisting 'C:\\Program Files\\NoSuchDir\\..\\x'"] = os.path.realpath("C:\\Program Files\\NoSuchDir\\..\\x")

# Git Bash 的路径映射（若装了 Git for Windows）
git = subprocess.run(["where.exe", "git"], capture_output=True).stdout.decode("utf-8", "replace").split("\r\n")[0]
bash = os.path.join(os.path.dirname(os.path.dirname(git)), "bin", "bash.exe") if git else ""
res["git_bash_found"] = os.path.exists(bash)
if os.path.exists(bash):
    out = subprocess.run([bash, "-c", 'for p in / /tmp /usr /c/Users "$HOME" /d/x ./; do printf "%s => " "$p"; cygpath -w "$p"; done'],
                         capture_output=True)
    res["git_bash_cygpath"] = [l.replace(home, "~") for l in out.stdout.decode("utf-8", "replace").splitlines()]

print(json.dumps(res, indent=1, ensure_ascii=True))
