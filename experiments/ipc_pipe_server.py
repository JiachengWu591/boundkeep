"""Prototype: named-pipe server via ctypes with explicit DACL (current user only),
PIPE_REJECT_REMOTE_CLIENTS, FIRST_PIPE_INSTANCE, and a pool of pre-created instances."""
import ctypes, sys, threading, time
from ctypes import wintypes as wt

PIPE = sys.argv[1]
POOL = int(sys.argv[2]) if len(sys.argv) > 2 else 8

k32 = ctypes.WinDLL("kernel32", use_last_error=True)
adv = ctypes.WinDLL("advapi32", use_last_error=True)


class SECURITY_ATTRIBUTES(ctypes.Structure):
    _fields_ = [("nLength", wt.DWORD), ("lpSecurityDescriptor", wt.LPVOID), ("bInheritHandle", wt.BOOL)]


k32.GetCurrentProcess.restype = wt.HANDLE
k32.CloseHandle.argtypes = [wt.HANDLE]
k32.CloseHandle.restype = wt.BOOL
k32.CreateNamedPipeW.argtypes = [wt.LPCWSTR, wt.DWORD, wt.DWORD, wt.DWORD, wt.DWORD, wt.DWORD, wt.DWORD,
                                 ctypes.POINTER(SECURITY_ATTRIBUTES)]
k32.CreateNamedPipeW.restype = wt.HANDLE
k32.ConnectNamedPipe.argtypes = [wt.HANDLE, wt.LPVOID]
k32.ConnectNamedPipe.restype = wt.BOOL
k32.DisconnectNamedPipe.argtypes = [wt.HANDLE]
k32.DisconnectNamedPipe.restype = wt.BOOL
k32.FlushFileBuffers.argtypes = [wt.HANDLE]
k32.FlushFileBuffers.restype = wt.BOOL
k32.ReadFile.argtypes = [wt.HANDLE, wt.LPVOID, wt.DWORD, ctypes.POINTER(wt.DWORD), wt.LPVOID]
k32.ReadFile.restype = wt.BOOL
k32.WriteFile.argtypes = [wt.HANDLE, wt.LPVOID, wt.DWORD, ctypes.POINTER(wt.DWORD), wt.LPVOID]
k32.WriteFile.restype = wt.BOOL
adv.OpenProcessToken.argtypes = [wt.HANDLE, wt.DWORD, ctypes.POINTER(wt.HANDLE)]
adv.OpenProcessToken.restype = wt.BOOL
adv.GetTokenInformation.argtypes = [wt.HANDLE, ctypes.c_int, wt.LPVOID, wt.DWORD, ctypes.POINTER(wt.DWORD)]
adv.GetTokenInformation.restype = wt.BOOL
adv.ConvertSidToStringSidW.argtypes = [wt.LPVOID, ctypes.POINTER(wt.LPWSTR)]
adv.ConvertSidToStringSidW.restype = wt.BOOL
adv.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [wt.LPCWSTR, wt.DWORD,
                                                                     ctypes.POINTER(wt.LPVOID), wt.LPVOID]
adv.ConvertStringSecurityDescriptorToSecurityDescriptorW.restype = wt.BOOL


def user_sid():
    tok = wt.HANDLE()
    if not adv.OpenProcessToken(k32.GetCurrentProcess(), 0x0008, ctypes.byref(tok)):  # TOKEN_QUERY
        raise ctypes.WinError(ctypes.get_last_error())
    need = wt.DWORD()
    adv.GetTokenInformation(tok, 1, None, 0, ctypes.byref(need))  # TokenUser
    buf = ctypes.create_string_buffer(need.value)
    if not adv.GetTokenInformation(tok, 1, buf, need, ctypes.byref(need)):
        raise ctypes.WinError(ctypes.get_last_error())
    k32.CloseHandle(tok)
    psid = ctypes.c_void_p.from_buffer(buf).value
    s = wt.LPWSTR()
    if not adv.ConvertSidToStringSidW(psid, ctypes.byref(s)):
        raise ctypes.WinError(ctypes.get_last_error())
    return s.value


sddl = "D:P(A;;GA;;;%s)" % user_sid()
psd = wt.LPVOID()
if not adv.ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, 1, ctypes.byref(psd), None):
    raise ctypes.WinError(ctypes.get_last_error())
sa = SECURITY_ATTRIBUTES(ctypes.sizeof(SECURITY_ATTRIBUTES), psd, False)

PIPE_ACCESS_DUPLEX = 0x3
FIRST_INSTANCE = 0x00080000
MODE = 0x0 | 0x0 | 0x0 | 0x8  # BYTE | READMODE_BYTE | WAIT | REJECT_REMOTE_CLIENTS
INVALID = ctypes.c_void_p(-1).value


def make_instance(first):
    flags = PIPE_ACCESS_DUPLEX | (FIRST_INSTANCE if first else 0)
    h = k32.CreateNamedPipeW(PIPE, flags, MODE, 255, 65536, 65536, 0, ctypes.byref(sa))
    if h in (None, 0, INVALID):
        raise ctypes.WinError(ctypes.get_last_error())
    return h


def serve(h):
    rb = ctypes.create_string_buffer(4096)
    n = wt.DWORD()
    w = wt.DWORD()
    while True:
        ok = k32.ConnectNamedPipe(h, None)
        if not ok and ctypes.get_last_error() != 535:  # ERROR_PIPE_CONNECTED
            time.sleep(0.01)
            continue
        buf = b""
        while b"\n" not in buf:
            if not k32.ReadFile(h, rb, 4096, ctypes.byref(n), None) or n.value == 0:
                break
            buf += rb.raw[: n.value]
        line = buf.split(b"\n", 1)[0]
        if line.startswith(b"HANG"):
            time.sleep(3600)
        elif buf:
            reply = b'{"permissionDecision":"ask"}\n'
            k32.WriteFile(h, reply, len(reply), ctypes.byref(w), None)
            k32.FlushFileBuffers(h)
        k32.DisconnectNamedPipe(h)


first = make_instance(True)
handles = [first] + [make_instance(False) for _ in range(POOL - 1)]
for h in handles:
    threading.Thread(target=serve, args=(h,), daemon=True).start()
print("READY sddl=" + sddl, flush=True)
time.sleep(600)
