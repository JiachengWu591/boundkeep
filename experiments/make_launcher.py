"""用 pip 自带的 distlib 生成 Windows 控制台启动器 .exe（与 pip 安装 console_scripts 时的做法相同）。

用途：E16 / E10 对比"启动器 .exe"与 "python.exe -I -S <脚本>" 两种 exec 写法；E16 的含空格与中文的 hook 路径。
用法：python experiments/make_launcher.py <目标目录> [脚本，默认 probe_hook.py]
生成的 exe = 启动器 + shebang（指向当前解释器）+ 内嵌的 zip（脚本作为 __main__.py）。
注意：脚本被内嵌后 __file__ 在 zip 里，所以运行时要用环境变量 BK_PROBE_DIR 指定记录目录。
"""
import os
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))


def build(dest_dir, script=os.path.join(HERE, "probe_hook.py"), python=sys.executable):
    from pip._vendor.distlib.scripts import ScriptMaker

    os.makedirs(dest_dir, exist_ok=True)
    src = tempfile.mkdtemp(prefix="bk_launcher_src_")
    name = os.path.splitext(os.path.basename(script))[0] + ".py"
    with open(script, "rb") as f:
        data = f.read()
    with open(os.path.join(src, name), "wb") as f:
        f.write(b"#!python\n" + data)  # ScriptMaker 只对带 shebang 的脚本生成启动器
    maker = ScriptMaker(src, dest_dir, add_launchers=True)
    maker.executable = python
    maker.variants = {""}
    maker.clobber = True
    return maker.make(name)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    made = build(sys.argv[1], *(sys.argv[2:3] or []))
    print("\n".join(made))
