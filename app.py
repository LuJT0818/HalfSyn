import ipaddress
import subprocess
import threading
from pathlib import Path

from flask import Flask, render_template_string, request

BASE_DIR = Path(__file__).resolve().parent
MAIN = BASE_DIR / "main"
LOCK = threading.Lock()

app = Flask(__name__)

PAGE = """<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<title>TCP 半连接扫描</title>
<style>
  body { font-family: sans-serif; max-width: 720px; margin: 40px auto; }
  label { display: block; margin-top: 14px; }
  input { width: 100%; padding: 8px; box-sizing: border-box; }
  button { margin-top: 18px; padding: 8px 20px; }
  .box { margin-top: 24px; padding: 14px; border: 1px solid #ccc; }
  .open    { color: green; }
  .closed  { color: #c00; }
  .timeout { color: #b60; }
  .error   { color: #555; }
  pre { white-space: pre-wrap; background: #f5f5f5; padding: 10px; }
</style>
</head>
<body>
  <h2>TCP 半连接扫描</h2>

  <form method="post">
    <label>源 IP
      <input name="src" value="{{ src|e }}" required>
    </label>
    <label>目标 IP
      <input name="dst" value="{{ dst|e }}" required>
    </label>
    <label>目标端口
      <input name="port" value="{{ port|e }}" required>
    </label>
    <button type="submit">开始扫描</button>
  </form>

  {% if result %}
  <div class="box">
    <p><strong class="{{ result[1] }}">{{ result[0] }}</strong></p>
    <pre>{{ raw|e }}</pre>
  </div>
  {% endif %}
</body>
</html>
"""


def iface_for(ip):
    """根据本机 IPv4 地址查找网卡名，例如 127.0.0.1 -> lo。"""
    try:
        out = subprocess.check_output(
            ["ip", "-o", "-4", "addr", "show"],
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=2,
        )
    except (OSError, subprocess.SubprocessError):
        return None

    for line in out.splitlines():
        parts = line.split()
        if (len(parts) >= 4 and parts[2] == "inet"
                and parts[3].split("/")[0] == ip):
            return parts[1]
    return None


def parse_result(output):
    if "端口开放" in output or ("SYN=1" in output and "RST=0" in output):
        return ("端口开放", "open")
    if "端口关闭" in output or "RST=1" in output:
        return ("端口关闭", "closed")
    if "超时" in output:
        return ("无响应 / 可能被过滤", "timeout")
    return ("扫描失败", "error")


@app.route("/", methods=["GET", "POST"])
def index():
    src = request.form.get("src", "127.0.0.1")
    dst = request.form.get("dst", "127.0.0.1")
    port = request.form.get("port", "80")
    result = None
    raw = ""

    if request.method == "POST":
        try:
            src_ip = str(ipaddress.IPv4Address(src.strip()))
            dst_ip = str(ipaddress.IPv4Address(dst.strip()))
            port_num = int(port)

            if not 1 <= port_num <= 65535:
                raise ValueError("端口必须是 1~65535")

            iface = iface_for(src_ip)
            if iface is None:
                raise ValueError(f"找不到源 IP {src_ip} 对应的本机网卡")

            cmd = [str(MAIN), src_ip, dst_ip, str(port_num), iface]

            # main 固定使用源端口 40000，串行执行避免多次扫描互相干扰
            with LOCK:
                proc = subprocess.run(
                    cmd,
                    cwd=BASE_DIR,
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    timeout=10,
                )

            raw = f"使用网卡：{iface}\n"
            raw += (proc.stdout or "") + (proc.stderr or "")
            result = parse_result(raw)

        except subprocess.TimeoutExpired:
            result = ("扫描超时", "timeout")
            raw = "main 进程超过 10 秒仍未返回"
        except Exception as exc:
            result = ("执行失败", "error")
            raw = str(exc)

    return render_template_string(
        PAGE, src=src, dst=dst, port=port,
        result=result, raw=raw
    )


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)