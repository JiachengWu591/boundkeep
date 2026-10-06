"""E10：hook 客户端的冷启动耗时，以及经命名管道与一个空服务往返的耗时。

用法：python experiments/bench_hook_cold_start.py [次数，默认 60]
测的是"从启动进程到进程退出"的墙钟时间（含解释器启动），每种写法跑 N 次，报告 p50 / p95 / 最小 / 最大。
另报"新生成的 .exe 第一次运行"的耗时，作为杀毒软件首次扫描的代理（不是对 Defender 的直接测量）。
这是微基准，不是产品评测：数字只代表本机当时的状态（记录了机器与系统版本）。
"""
import json
import os
import platform
import statistics
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
PY = sys.executable
PROBE = os.path.join(HERE, "probe_hook.py")
CLIENT = os.path.join(HERE, "ipc_pipe_client.py")
SERVER = os.path.join(HERE, "ipc_pipe_server.py")
EVENT = json.dumps({
    "session_id": "s", "transcript_path": "C:\\x\\s.jsonl", "cwd": "E:\\bk-lab", "permission_mode": "default",
    "hook_event_name": "PreToolUse", "tool_name": "PowerShell",
    "tool_input": {"command": "Write-Output 'hi'", "description": "d"}, "tool_use_id": "t",
}).encode("utf-8")


def pct(xs, p):
    xs = sorted(xs)
    return xs[min(len(xs) - 1, int(len(xs) * p))]


def timeit(cmd, n, env):
    ts = []
    bad = 0
    for _ in range(n):
        t0 = time.perf_counter()
        p = subprocess.run(cmd, input=EVENT, capture_output=True, env=env)
        ts.append((time.perf_counter() - t0) * 1000)
        if p.returncode != 0:
            bad += 1
    return {"n": n, "p50_ms": round(statistics.median(ts), 1), "p95_ms": round(pct(ts, 0.95), 1),
            "min_ms": round(min(ts), 1), "max_ms": round(max(ts), 1), "nonzero_rc": bad}


def main():
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 60
    tmp = tempfile.mkdtemp(prefix="bk_bench_")
    env = dict(os.environ, BK_PROBE_DIR=os.path.join(tmp, "raw"))
    cpu = subprocess.run(["powershell", "-NoProfile", "-Command", "(Get-CimInstance Win32_Processor).Name"],
                         capture_output=True).stdout.decode("ascii", "replace").strip() if os.name == "nt" else platform.processor()
    res = {"machine": {"os": platform.platform(), "cpu": cpu, "python": sys.version.split()[0], "cpus": os.cpu_count()}}

    res["bare: python -I -S -c pass"] = timeit([PY, "-I", "-S", "-c", "pass"], n, env)
    res["bare: python -I -c pass (with site)"] = timeit([PY, "-I", "-c", "pass"], n, env)
    res["recorder: python -I -S probe_hook.py"] = timeit([PY, "-I", "-S", PROBE, "bench"], n, env)

    sys.path.insert(0, HERE)
    import make_launcher
    exe_dir = os.path.join(tmp, "bin")
    exe = make_launcher.build(exe_dir, python=PY)[0]
    t0 = time.perf_counter()
    subprocess.run([exe, "bench"], input=EVENT, capture_output=True, env=env)
    res["exe launcher: FIRST run after creation (ms)"] = round((time.perf_counter() - t0) * 1000, 1)
    res["recorder: launcher .exe"] = timeit([exe, "bench"], n, env)

    shim = os.path.expandvars(r"%LOCALAPPDATA%\mise\shims\python.exe")
    if os.path.exists(shim):
        res["recorder: mise shim python.exe -I -S"] = timeit([shim, "-I", "-S", PROBE, "bench"], n, env)

    # 命名管道往返：起一个多实例的 ctypes 服务端，hook 形状的客户端每次新进程
    pipe = "\\\\.\\pipe\\bk-bench-%d" % os.getpid()
    srv = subprocess.Popen([PY, "-I", SERVER, pipe, "8"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    first = srv.stdout.readline()
    if first.startswith(b"READY"):
        res["pipe client: python -I -S ipc_pipe_client.py (round trip)"] = timeit([PY, "-I", "-S", CLIENT, pipe], n, env)
        client_exe = make_launcher.build(os.path.join(tmp, "binc"), CLIENT, python=PY)[0]
        res["pipe client: launcher .exe (round trip)"] = timeit([client_exe, pipe], n, env)
    else:
        res["pipe client"] = "server failed: %r" % first
    srv.kill()
    # 常驻进程没起：应立刻降级
    res["pipe client: daemon down (FileNotFoundError path)"] = timeit([PY, "-I", "-S", CLIENT, pipe + "-absent"], max(10, n // 3), env)

    out = json.dumps(res, indent=1, ensure_ascii=True)
    print(out)
    os.makedirs(os.path.join(HERE, "raw"), exist_ok=True)
    with open(os.path.join(HERE, "raw", "bench_hook_cold_start.json"), "w", encoding="ascii") as f:
        f.write(out)


if __name__ == "__main__":
    main()
