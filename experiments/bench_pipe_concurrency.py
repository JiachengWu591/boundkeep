"""命名管道并发原型基准（E10 / E19 的前身；规格 §5.1）。仅标准库，只能在 Windows 上运行。

对每种服务端（asyncio 基线、ctypes 实例池）各做：
  - 顺序往返 200 次（同时是热身；必须全部成功，记录 p50 / p95）；
  - "不重试"并发突发：预算为 0，第一次遇到 OSError 就失败，看"管道忙"有多常见；
  - "重试"并发突发：按 hook 客户端的写法，FileNotFoundError 立即失败，其他 OSError 退避重试，总预算 2 秒；
  - 读出管道的 DACL（用 .NET 的 NamedPipeClientStream.GetAccessControl；Get-Acl 读不了管道）。
输出一个 JSON；SID、用户名与机器名已脱敏。

用法：python experiments\\bench_pipe_concurrency.py [--threads 32] [--per 20] [--reps 3] [--pools 1,8] [--out 文件]
"""
import argparse
import collections
import json
import os
import platform
import re
import subprocess
import sys
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
REQ = b'{"tool":"Bash"}'


def scrub(text):
    """去掉 SID、用户名、机器名，防止进入将提交的证据。"""
    text = re.sub(r"S-1-5-21-[\d-]+", "S-1-5-21-<id>", text)
    for var, repl in (("USERNAME", "<user>"), ("COMPUTERNAME", "<host>")):
        val = os.environ.get(var)
        if val:
            text = re.sub(re.escape(val), repl, text, flags=re.I)
    return text


def call(pipe, budget, stats, lock):
    end = time.monotonic() + budget
    delay = 0.0005
    while True:
        try:
            f = open(pipe, "r+b", buffering=0)
            break
        except FileNotFoundError:
            raise
        except OSError as e:
            with lock:
                stats["retries"] += 1
                stats["kinds"]["%s errno=%s winerror=%s" % (type(e).__name__, e.errno, getattr(e, "winerror", None))] += 1
            if time.monotonic() >= end:
                raise
            time.sleep(delay)
            delay = min(delay * 2, 0.02)
    try:
        f.write(REQ + b"\n")
        buf = b""
        while b"\n" not in buf:
            chunk = f.read(4096)
            if not chunk:
                break
            buf += chunk
        if not buf.strip():
            raise OSError("empty reply")
        return buf
    finally:
        f.close()


def burst(pipe, nthreads, per, budget):
    stats = {"retries": 0, "kinds": collections.Counter()}
    lock = threading.Lock()
    lat, errs = [], []

    def worker():
        for _ in range(per):
            t0 = time.perf_counter()
            try:
                call(pipe, budget, stats, lock)
                dt = (time.perf_counter() - t0) * 1000
                with lock:
                    lat.append(dt)
            except Exception as e:  # noqa: BLE001
                with lock:
                    errs.append("%s errno=%s" % (type(e).__name__, getattr(e, "errno", None)))

    ths = [threading.Thread(target=worker) for _ in range(nthreads)]
    t0 = time.perf_counter()
    for t in ths:
        t.start()
    for t in ths:
        t.join()
    wall = time.perf_counter() - t0
    lat.sort()

    def pc(p):
        return round(lat[min(len(lat) - 1, int(len(lat) * p))], 2) if lat else None

    return {
        "calls": nthreads * per, "ok": len(lat), "errors": len(errs),
        "error_kinds": dict(collections.Counter(errs)),
        "busy_retries": stats["retries"], "busy_kinds": dict(stats["kinds"]),
        "wall_s": round(wall, 3), "p50_ms": pc(.5), "p95_ms": pc(.95), "p99_ms": pc(.99),
        "max_ms": round(lat[-1], 2) if lat else None,
    }


def acl_of(name):
    ps = (
        "try { $c = New-Object System.IO.Pipes.NamedPipeClientStream('.', '%s', "
        "[System.IO.Pipes.PipeDirection]::InOut); $c.Connect(3000); "
        "$a = $c.GetAccessControl(); $a.GetSecurityDescriptorSddlForm('Access'); "
        "$a.Access | ForEach-Object { '{0} | {1} | {2}' -f $_.IdentityReference, $_.PipeAccessRights, $_.AccessControlType }; "
        "$c.Dispose() } catch { 'ERR: ' + $_.Exception.Message }"
    ) % name
    out = subprocess.run(["powershell", "-NoProfile", "-Command", ps], capture_output=True, timeout=60)
    return [scrub(x) for x in out.stdout.decode("ascii", "replace").strip().splitlines()[:8]]


def run_variant(label, script, extra, a):
    name = "boundkeep-probe-%d-%s" % (os.getpid(), label)
    pipe = "\\\\.\\pipe\\" + name
    srv = subprocess.Popen([sys.executable, "-I", os.path.join(HERE, script), pipe] + extra,
                           stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    try:
        first = srv.stdout.readline().strip().decode("ascii", "replace")
        r = {"server": scrub(first)[:160]}
        if not first.startswith("READY"):
            r["server_output_rest"] = scrub(srv.stdout.read(600).decode("ascii", "replace"))
            return r
        stats = {"retries": 0, "kinds": collections.Counter()}
        lock = threading.Lock()
        seq = []
        for _ in range(a.sequential):
            t0 = time.perf_counter()
            call(pipe, 2.0, stats, lock)
            seq.append((time.perf_counter() - t0) * 1000)
        seq.sort()
        r["sequential"] = {
            "calls": len(seq), "p50_ms": round(seq[len(seq) // 2], 3),
            "p95_ms": round(seq[int(len(seq) * .95)], 3), "max_ms": round(seq[-1], 3),
            "busy_retries": stats["retries"],
        }
        r["no_retry"] = [burst(pipe, a.threads, a.per, 0.0) for _ in range(a.reps)]
        r["with_retry"] = [burst(pipe, a.threads, a.per, 2.0) for _ in range(a.reps)]
        r["acl"] = acl_of(name)
        return r
    finally:
        srv.kill()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--threads", type=int, default=32)
    ap.add_argument("--per", type=int, default=20)
    ap.add_argument("--reps", type=int, default=3)
    ap.add_argument("--pools", default="1,8")
    ap.add_argument("--sequential", type=int, default=200, help="无并发的顺序往返次数（同时是热身）")
    ap.add_argument("--out")
    a = ap.parse_args()
    results = {
        "env": {"python": sys.version.split()[0], "os": platform.platform(), "cpus": os.cpu_count(),
                "threads": a.threads, "calls_per_thread": a.per, "reps": a.reps},
        "variants": {},
    }
    results["variants"]["asyncio start_serving_pipe (1 pending instance)"] = run_variant(
        "aio", "ipc_pipe_server_asyncio.py", [], a)
    for p in a.pools.split(","):
        results["variants"]["ctypes pool=%s, DACL=current user, REJECT_REMOTE" % p] = run_variant(
            "ct" + p, "ipc_pipe_server.py", [p], a)
    text = json.dumps(results, indent=1, ensure_ascii=True)
    print(text)
    if a.out:
        with open(a.out, "w", encoding="ascii", newline="\n") as f:
            f.write(text + "\n")


if __name__ == "__main__":
    main()
