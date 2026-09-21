#!/usr/bin/env python3
"""诊断：为什么 IDE 面板能看到可领活动，而脚本直连 campaigns 列表为空。
假设：活动可见性绑定 webview 的设备 Cookie（cna）。本脚本在你本机解密 IDE
Cookie 库取 cna，分别用 无Cookie / 有Cookie 请求 campaigns 列表对比。
只输出结论与脱敏摘要，不打印任何凭据明文。
用法：python scripts/diag_campaign_visibility.py [cn|global]
"""
import base64
import json
import os
import sqlite3
import shutil
import sys
import tempfile
import urllib.request
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import importlib.util
spec = importlib.util.spec_from_file_location("et", os.path.join(os.path.dirname(os.path.abspath(__file__)), "export_token.py"))
et = importlib.util.module_from_spec(spec)
spec.loader.exec_module(et)

PROFILE = sys.argv[1] if len(sys.argv) > 1 else "cn"
profile = et.PROFILES[PROFILE]
data_dir = Path(os.path.expanduser(profile["data_dir"]))


def os_crypt_key():
    ls = json.loads((data_dir / "Local State").read_text(encoding="utf-8"))
    enc = base64.b64decode(ls["os_crypt"]["encrypted_key"])
    return et.dpapi_unprotect(enc[5:])


def get_campaigns(token, cookie=None):
    req = urllib.request.Request(
        profile["api_base_campaigns"],
        headers={"Authorization": f"Bearer {token}", **({"Cookie": cookie} if cookie else {})},
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return json.loads(r.read().decode("utf-8"))
    except Exception as e:
        return {"_error": str(e)}


# 补上 campaigns 地址（export_token.PROFILES 没有该字段，这里按 openApi 域名拼）
OPENAPI = {"cn": "https://openapi.qoder.com.cn", "global": "https://openapi.qoder.sh"}[PROFILE]
profile["api_base_campaigns"] = OPENAPI + "/sash/api/v1/me/campaigns"

auth = et.load_token(profile)
token = auth["token"]

ckdb = data_dir / "Network" / "Cookies"
cookie_pairs = []
if ckdb.exists():
    try:
        tmp = Path(tempfile.mkdtemp()) / "Cookies"
        shutil.copy(ckdb, tmp)
        key = os_crypt_key()
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        con = sqlite3.connect(tmp)
        for host, name, ev in con.execute(
            "select host_key,name,encrypted_value from cookies where host_key like '%qoder%' or host_key like '%alicdn%'"
        ).fetchall():
            if ev and ev[:3] == b"v10":
                try:
                    val = AESGCM(key).decrypt(ev[3:15], ev[15:], None).decode("utf-8", "replace")
                    cookie_pairs.append((host, name, val))
                except Exception:
                    pass
    except Exception as e:
        print("cookie 库读取失败:", type(e).__name__, str(e)[:80])

names = [n for _, n, _ in cookie_pairs]
print(f"profile={PROFILE} | cookie 条目: {len(cookie_pairs)} 个，名称: {sorted(set(names))}")

def summarize(d):
    if "_error" in d:
        return f"请求失败: {d['_error'][:60]}"
    cs = d.get("campaigns", [])
    return f"show={d.get('showCampaign')} claimable={d.get('claimable')} campaigns={[(c.get('campaignKey'), c.get('claimStatus')) for c in cs]}"

print("A) 无 Cookie           :", summarize(get_campaigns(token)))

for host, name, val in cookie_pairs:
    d = get_campaigns(token, cookie=f"{name}={val}")
    s = summarize(d)
    hit = ("campaigns=[(" in s) or ("claimable=True" in s) or ("show=True" in s)
    print(f"B) 仅 {name}@{host[:22]:22} :", s, "  <== 出现活动!" if hit else "")

if cookie_pairs:
    joined = "; ".join(f"{n}={v}" for _, n, v in cookie_pairs)
    print("C) 全部 Cookie        :", summarize(get_campaigns(token, cookie=joined)))
