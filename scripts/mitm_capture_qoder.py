# mitmproxy 脚本：记录本机 Qoder IDE 发往 qoder 域名的请求，用于定位签到真实接口。
# 用法：mitmdump -s scripts/mitm_capture_qoder.py --listen-port 8080
import json
import os
from datetime import datetime

from mitmproxy import http

LOG = os.path.join(os.path.dirname(__file__), "..", "data", "qoder-capture.log")
SENSITIVE = ("authorization", "cookie", "token", "refresh")


def redact(v: str) -> str:
    return (v[:6] + "…<redacted>") if len(v) > 12 else v


def response(flow: http.HTTPFlow):
    host = flow.request.pretty_host
    if "qoder" not in host:
        return
    rec = {
        "ts": datetime.now().isoformat(timespec="seconds"),
        "method": flow.request.method,
        "url": flow.request.pretty_url,
        "status": flow.response.status_code,
        "headers": {k.lower(): redact(v) for k, v in flow.request.headers.items()
                    if any(s in k.lower() for s in SENSITIVE)},
    }
    try:
        body = flow.request.get_text() or ""
        if body:
            rec["req_body"] = (json.dumps(json.loads(body), ensure_ascii=False)[:500]
                               if body[:1] in "[{" else body[:300])
    except Exception:
        pass
    try:
        resp = flow.response.get_text() or ""
        rec["resp_head"] = resp[:400]
    except Exception:
        pass
    with open(LOG, "a", encoding="utf-8") as f:
        f.write(json.dumps(rec, ensure_ascii=False) + "\n")
