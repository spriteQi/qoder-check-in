#!/usr/bin/env python3
"""本机提取 Qoder（CN/Global）登录 token 并输出为 GitHub Secrets 可用格式。

支持 macOS（钥匙串 + safeStorage AES-CBC）与 Windows（Local State + DPAPI + AES-GCM）。
需依赖：pip install cryptography

用法：
  python scripts/export_token.py              # 全部端，交互式说明 + gh 命令
  python scripts/export_token.py cn           # 只导 CN
  python scripts/export_token.py --raw        # 仅输出 NAME=VALUE 行（网页端粘贴用/管道）
  python scripts/export_token.py --gh         # 仅输出 `gh secret set ...` 命令
  python scripts/export_token.py --gh | bash  # 直接写入当前仓库的 Secrets（需 gh 已登录）
"""
import argparse
import base64
import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

IS_WIN = sys.platform == "win32"
if IS_WIN:
    _APP_DATA = os.environ.get("APPDATA", str(Path.home() / "AppData/Roaming"))
    def _default_dir(app_id): return str(Path(_APP_DATA) / app_id)
else:
    def _default_dir(app_id): return f"~/Library/Application Support/{app_id}"

PROFILES = {
    "cn": {
        "label": "Qoder CN",
        "secret": "QODER_TOKEN_CN",
        "data_dir": os.environ.get("QODER_DATA_DIR")
        or os.environ.get("QODER_DATA_DIR_CN")
        or _default_dir("com.qodercn.app.stable"),
        "keychain_services": [s.strip() for s in (os.environ.get("QODER_KEYCHAIN_SERVICES")
            or os.environ.get("QODER_KEYCHAIN_SERVICES_CN")
            or "Qoder CN App Safe Storage").split(",") if s.strip()],
    },
    "global": {
        "label": "Qoder Global",
        "secret": "QODER_TOKEN_GLOBAL",
        "data_dir": os.environ.get("QODER_DATA_DIR_GLOBAL")
        or _default_dir("com.qoder.app.stable"),
        "keychain_services": [s.strip() for s in (os.environ.get("QODER_KEYCHAIN_SERVICES_GLOBAL")
            or "Qoder Safe Storage").split(",") if s.strip()],
    },
}


def keychain_password(service: str) -> str:
    return subprocess.run(
        ["security", "find-generic-password", "-s", service, "-w"],
        check=True, capture_output=True, text=True,
    ).stdout.strip()


def decrypt_safe_storage(blob: bytes, password: str) -> bytes:
    """Electron safeStorage v10：PBKDF2-SHA1(salt=saltysalt, iters=1003, 16B) + AES-128-CBC(IV=0x20*16)。"""
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives import padding

    if blob[:3] != b"v10":
        raise ValueError("unexpected prefix (not v10)")
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes

    dk = PBKDF2HMAC(algorithm=hashes.SHA1(), length=16, salt=b"saltysalt", iterations=1003)
    aes_key = dk.derive(password.encode("utf-8"))
    dec = Cipher(algorithms.AES(aes_key), modes.CBC(b"\x20" * 16)).decryptor()
    padded = dec.update(blob[3:]) + dec.finalize()
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    return unpadder.update(padded) + unpadder.finalize()


def dpapi_unprotect(data: bytes) -> bytes:
    """Windows 当前用户 DPAPI 解密（CryptUnprotectData）。"""
    import ctypes
    import ctypes.wintypes as wt

    class BLOB(ctypes.Structure):
        _fields_ = [("cb", wt.DWORD), ("pb", ctypes.POINTER(ctypes.c_byte))]

    buf = ctypes.create_string_buffer(data, len(data))
    inb = BLOB(len(data), ctypes.cast(buf, ctypes.POINTER(ctypes.c_byte)))
    outb = BLOB()
    if not ctypes.windll.crypt32.CryptUnprotectData(ctypes.byref(inb), None, None, None, None, 0, ctypes.byref(outb)):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        return ctypes.string_at(outb.pb, outb.cb)
    finally:
        ctypes.windll.kernel32.LocalFree(outb.pb)


def decrypt_os_crypt(data_dir: Path, blob: bytes) -> bytes:
    """Chromium/Electron os_crypt（Windows 上的 v10）：Local State 的 DPAPI 包裹密钥 + AES-256-GCM。"""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    if blob[:3] != b"v10":
        raise ValueError("unexpected prefix (not v10)")
    local_state = json.loads((data_dir / "Local State").read_text(encoding="utf-8"))
    enc_key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])
    if enc_key[:5] != b"DPAPI":
        raise ValueError("encrypted_key 不是 DPAPI 包裹格式")
    key = dpapi_unprotect(enc_key[5:])
    iv, ciphertext = blob[3:15], blob[15:]
    return AESGCM(key).decrypt(iv, ciphertext, None)


def load_token(profile: dict) -> dict:
    data_dir = Path(os.path.expanduser(profile["data_dir"]))
    auth_file = data_dir / "auth.v1.dat"
    if not auth_file.exists():
        raise FileNotFoundError(f"缺少凭据文件 {auth_file}（该端 IDE 未安装/未登录？）")
    blob = auth_file.read_bytes()
    if IS_WIN:
        return json.loads(decrypt_os_crypt(data_dir, blob))
    if sys.platform != "darwin":
        raise RuntimeError("仅支持 macOS 钥匙串或 Windows DPAPI")
    last_err: Exception | None = None
    for service in profile["keychain_services"]:
        try:
            return json.loads(decrypt_safe_storage(blob, keychain_password(service)))
        except subprocess.CalledProcessError:
            last_err = RuntimeError(f"钥匙串条目「{service}」读取被拒绝或未找到")
        except Exception as e:  # 换下一个服务名重试
            last_err = e
    raise last_err or RuntimeError("凭据解密失败")


def format_expiry(expires_at, token: str) -> str:
    if expires_at:
        try:
            if isinstance(expires_at, (int, float)) or (isinstance(expires_at, str) and expires_at.isdigit()):
                return datetime.fromtimestamp(int(expires_at), tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
            return datetime.fromisoformat(str(expires_at).replace("Z", "+00:00")).astimezone().strftime("%Y-%m-%d %H:%M %Z")
        except Exception:
            pass
    return jwt_expiry(token)


def jwt_expiry(token: str) -> str:
    try:
        payload = json.loads(base64.urlsafe_b64decode(token.split(".")[1] + "=="))
        exp = payload.get("exp")
        return datetime.fromtimestamp(exp, tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC") if exp else "未知"
    except Exception:
        return "未知"


def main() -> int:
    ap = argparse.ArgumentParser(description="提取 Qoder 登录 token 为 GitHub Secrets 可用格式")
    ap.add_argument("profiles", nargs="?", default="all", help="cn | global | all（逗号分隔可选多端）")
    ap.add_argument("--raw", action="store_true", help="仅输出 NAME=VALUE 行")
    ap.add_argument("--gh", action="store_true", help="仅输出 gh secret set 命令")
    args = ap.parse_args()

    names = list(PROFILES) if args.profiles == "all" else [n.strip() for n in args.profiles.split(",")]
    rc = 0
    for name in names:
        profile = PROFILES.get(name)
        if not profile:
            print(f"未知端：{name}（可选 cn/global/all）", file=sys.stderr)
            rc = 1
            continue
        try:
            auth = load_token(profile)
            token = auth["token"]
        except Exception as e:
            print(f"⚠️  {profile['label']}: {e}", file=sys.stderr)
            rc = 1
            continue
        pairs = [(profile["secret"], token)]
        if auth.get("refreshToken"):
            pairs.append((profile["secret"].replace("_TOKEN_", "_REFRESH_TOKEN_"), auth["refreshToken"]))
        if args.raw:
            for name, value in pairs:
                print(f"{name}={value}")
        elif args.gh:
            for name, value in pairs:
                print(f"gh secret set {name} --body '{value}'")
        else:
            expire_hint = f"（token 到期：{format_expiry(auth.get('expiresAt'), token)}"
            if auth.get("refreshTokenExpiresAt"):
                expire_hint += f"，refreshToken 到期：{format_expiry(auth['refreshTokenExpiresAt'], '')}，续签轮换后以最新为准）"
            else:
                expire_hint += "）"
            print(f"# {profile['label']} {expire_hint}")
            for name, value in pairs:
                print(f"gh secret set {name} --body '{value}'")
            print(f"# 或在仓库 Settings → Secrets and variables → Actions 手动新建以下 Secret：")
            for name, value in pairs:
                print(f"{name}={value}")
            print()
    return rc


if __name__ == "__main__":
    sys.exit(main())
