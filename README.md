# qoder-check-in

Qoder「每日签到领 Credits」自动化，**同时支持 Qoder CN 与 Qoder Global**。纯 HTTP 实现：不开 GUI、不做屏幕点击、不存储任何凭据副本。两种运行方式：

- **本机 macOS（launchd）**：复用本机 Qoder IDE 已登录的凭据直接签到；
- **GitHub Actions 托管（推荐）**：无需开机，每天定时执行，结果邮件通知。

## 背景

Qoder 会不定期上线登录奖励活动（例如 2026-09-18 ~ 09-30，每天 10:00 起可领 100 Credits，入口是桌面端左下角用量面板的礼物图标）。本项目把「点一下礼物图标」变成每天自动执行一次的 HTTP 请求。

## 原理（逆向结论）

- 签到接口：`POST <gateway>/sash/api/v1/me/daily-check-in/claim`，状态查询为同前缀的 `GET .../status`，认证用 `Authorization: Bearer <token>`（token 即凭据文件里的 `dt-` 设备令牌）。
- CN 签到走 `https://gateway.qoder.com.cn`。**Global 侧实测（2026-09-20）：`gateway.qoder.com`/`gateway.qoder.sh` 无 DNS 记录，唯一可达的 sash 宿主是 `https://openapi.qoder.sh`，且其 daily-check-in 路由返回 404——即 Global 当前没有签到活动**。脚本将其识别为 `NO_ACTIVITY`（不计失败），Global 日后上线活动时无需改代码即可自动生效；如有出入可用 `QODER_API_BASE_GLOBAL` / 仓库 Variable 覆盖。
- ~~重复领取返回 `409 AlreadyExists`，可视为幂等成功~~ **已证伪（2026-09-20 实测）**：活动处于 `DISABLED` 时服务端同样返回 `409 AlreadyExists`，但并未发放任何 Credits。现在脚本以 `GET .../status` **前后双核验**判定真实结果：领取前查活动状态（非 ACTIVE 直接记 `ACTIVITY_OFF` 不再提交），领取后比对 `totalClaimDays/currentStreakDays/totalRewardCredits` 是否增长、`nextClaimAt` 是否推到未来；应答成功但状态无变化记 `UNVERIFIED`（计为失败）。
- **续签机制**（从官方客户端逆向）：`token`（`dt-` 前缀设备令牌，约 20 天）+ `refreshToken`（`drt-` 前缀，约 1 年）双令牌。续签接口 `POST {openApiBaseUrl}/api/v1/deviceToken/refresh`，请求体 `{"refresh_token":"drt-…"}`，响应为 snake_case（`device_token`/`refresh_token`/`expires_at`/`refresh_token_expires_at`），且 **refreshToken 每次都会轮换**。CN openApi 域名为 `https://openapi.qoder.com.cn`，Global 为 `https://openapi.qoder.sh`（取自 IDE 安装包 `openApiBaseUrl` 常量）。
- 本机凭据文件 `auth.v1.dat`（`{"token","refreshToken","expiresAt","refreshTokenExpiresAt","user",...}`）：macOS 为 Electron safeStorage（`v10` 前缀；钥匙串取密码；PBKDF2-SHA1，salt `saltysalt`，1003 次迭代，AES-128-CBC，IV 为 16 个 `0x20`）；Windows 为 Chromium os_crypt（`Local State` 中 DPAPI 包裹的 AES-256 密钥 + AES-GCM），`export_token.py` 两种平台均支持。
- Actions 托管模式无法解密本机钥匙串，改为通过仓库 Secrets 直传 token。
- 同一套 sash 服务也被 QoderWork/QwenWork CN 客户端使用（其旧签到活动已于 2026-07-30 截止）。

## 前置环境

| 项目 | 本机模式 | Actions 托管模式 |
|---|---|---|
| 系统 | macOS（依赖 `security` 命令与钥匙串） | 无需本机环境，fork/导入本仓库即可 |
| Node.js | ≥ 18（内置 `fetch`） | Runner 自带 |
| Qoder IDE | 已安装且已登录（对应端） | token/refreshToken 放入仓库 Secrets；配好 refreshToken 后临期自动续签+自动回写，Secret 约 1 年内无需手动维护 |

## 方式一：本机 macOS 定时

```bash
git clone https://github.com/hope0719/qoder-check-in.git
cd qoder-check-in
npm install          # 仅邮件通知需要；本机不装也能跑签到
./install.sh
```

首次运行会弹出 macOS 钥匙串授权对话框，输入登录密码并点「始终允许」——之后定时任务不再弹窗。

手动操作（profile 可选 `cn` / `global` / `all`，默认 `all`，未安装/未登录的端自动跳过）：

```bash
node scripts/qoder-checkin.mjs status        # 查看活动状态（只读）
node scripts/qoder-checkin.mjs claim         # 执行签到（幂等，两端都跑）
node scripts/qoder-checkin.mjs claim cn      # 只签 CN
```

退出码：`0` 成功或今日已领；`2` 无法获取凭据（未登录/钥匙串未授权/完全未提供 token）；`3` token 过期且自动续签也失败；`4` 接口报错（如活动未开始/已结束）。

## 方式二：GitHub Actions 托管 + 邮件通知

1. 复制本仓库（或 push 到自己的仓库）。
2. 在仓库 **Settings → Secrets and variables → Actions → Secrets** 中配置：

| Secret | 必填 | 说明 |
|---|---|---|
| `QODER_TOKEN_CN` | 两个至少其一 | CN 端 token（`dt-…`），本机执行 `python scripts/export_token.py cn` 导出 |
| `QODER_TOKEN_GLOBAL` | 两个至少其一 | Global 端 token，`export_token.py global` 导出；两者只配一个也能正常跑（另一端自动跳过） |
| `QODER_REFRESH_TOKEN_CN` | 建议 | CN 端 refreshToken（`drt-…`），export 脚本一并输出；配置后 token 临期/过期可由 Actions **自动续签**，无需每 20 天手动更新 |
| `QODER_REFRESH_TOKEN_GLOBAL` | 建议 | Global 端 refreshToken，同上 |
| `MAIL_CONFIG` | 否 | 邮件通知的全部参数，**一个 Secret 装多行 `KEY=VALUE`**（见下方示例）；不配置则不发邮件 |
| `GH_SECRETS_PAT` | 否 | 回写轮换凭据用。**GITHUB_TOKEN 无权调用仓库 Secrets API**（workflow `permissions:` 矩阵中也不存在 `secrets` 键），需新建 fine-grained PAT：只授权本仓库、权限仅 **Secrets: Read and write**、有效期最长 1 年 |

   `MAIL_CONFIG` 内容示例（**以 QQ 邮箱为例**，其他邮箱同理换 host）：

   ```text
   SMTP_HOST=smtp.qq.com
   SMTP_PORT=465
   SMTP_USER=123456789@qq.com
   SMTP_PASS=qqabcd efgh ijkl mnop
   MAIL_TO=123456789@qq.com,other@example.com
   # SMTP_SECURE=false   # 465 默认隐式 TLS；587 端口 STARTTLS 时设为 false
   # MAIL_FROM=自定义发件地址，默认取 SMTP_USER
   ```

   QQ 邮箱获取授权码：网页版 设置 → 账号 → 开启「SMTP服务」（需验证手机号）→ 生成 16 位授权码，填入 `SMTP_PASS`（不是 QQ 密码，空格可去掉）。`MAIL_TO` 支持逗号分隔多个收件人。

   另有可选 **Variables**：`QODER_API_BASE_GLOBAL`（覆盖 Global 网关域名）、`QODER_OPENAPI_BASE_GLOBAL`（覆盖 Global 续签域名）。
3. 工作流 `.github/workflows/daily-checkin.yml` 已配置 **每天 00:30（UTC+8）** 自动执行（cron 为 `30 16 * * *` UTC），也可在 Actions 页面手动「Run workflow」。若所有端都未提供任何 token，任务直接以退出码 2 失败。
4. **自动续签**：签到时若 token 剩余 <3 天（或接口返回 401），脚本自动用 refreshToken 调用续签接口换新。因续签会轮换 refreshToken，配置了 `GH_SECRETS_PAT` 时 workflow 会用 `gh secret set` 把新 token/refreshToken **回写到仓库 Secrets**，形成约 1 年的自动续命闭环；未配置则跳过回写并在邮件中提示（此时需约 20 天手动跑一次 `export_token.py`）。每次执行的邮件中会写明各端剩余有效期、是否发生了续签及回写结果。
5. 每次运行结束后，`scripts/notify.mjs` 汇总各端结果（成功/已领/跳过/失败/续签）发送邮件；仅当配置了 SMTP Secrets 才发送，否则跳过。

## 定制

环境变量：

- 通用：`QODER_CHECKIN_LOG`、`QODER_RESULT_FILE`（结果 JSON）、`QODER_REFRESHED_FILE`（续签轮换出的新凭据输出路径，供 CI 回写 Secrets）。
- CN：`QODER_TOKEN_CN`、`QODER_REFRESH_TOKEN_CN`、`QODER_API_BASE`/`QODER_API_BASE_CN`、`QODER_OPENAPI_BASE_CN`、`QODER_DATA_DIR`/`QODER_DATA_DIR_CN`、`QODER_KEYCHAIN_SERVICES`/`QODER_KEYCHAIN_SERVICES_CN`。
- Global：`QODER_TOKEN_GLOBAL`、`QODER_REFRESH_TOKEN_GLOBAL`、`QODER_API_BASE_GLOBAL`、`QODER_OPENAPI_BASE_GLOBAL`、`QODER_DATA_DIR_GLOBAL`、`QODER_KEYCHAIN_SERVICES_GLOBAL`。

本机定时规则在 `install.sh` 内 `__PRIMARY_*__` / `__FALLBACK_*__` 处修改后重跑安装。

## 声明

- 仅操作本机/Secrets 中当前登录的单一账号；不采集、不上传任何凭据（Actions 模式下 token 由你自行放入私有仓库 Secrets）。
- 接口细节来自对官方客户端的反向分析，可能随版本变化；请遵守 Qoder 服务条款，仅供个人学习使用。

## License

MIT
