#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
GLaDOS 自动签到 (2026 增强版)

功能特性：
1. 完整实现 2026 Challenge/Proof 签名防风控算法（SHA-256 加盐 + 2.7s 真实等待），避免被判定机器人或降权得 1 分
2. 智能多域名轮询容灾（glados.cloud / glados.rocks / glados.network）
3. 查验并展示当前总积分、积分增量、剩余 VIP 会员天数
4. 积分达标自动兑换会员天数（默认 500 分换 100 天）
5. PushPlus 微信通知推送（默认每次均推送，且自带防微信拦截敏感词脱敏）
6. 严格兼容原环境变量配置（仅需已有的 GLADOS_COOKIE 和 PUSHPLUS_TOKEN 即可无缝运行）
"""

import hashlib
import html
import json
import os
import re
import sys
import time
from datetime import datetime, timedelta, timezone

import requests

# 修复 Windows 终端 Unicode 编码输出
if sys.platform.startswith('win'):
    sys.stdout.reconfigure(encoding='utf-8')

# ================= 配置与常量 =================

DOMAINS = [
    "https://glados.one",
    "https://glados.cloud",
    "https://glados.rocks", 
    "https://glados.network",
]

# 2026 前端 613 模块逆向加盐与等待阈值
CHALLENGE_SALT = "glados-observe-v1"
CHALLENGE_MIN_WAIT_SECONDS = 2.7

DEFAULT_USER_AGENT = (
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
    'AppleWebKit/537.36 (KHTML, like Gecko) '
    'Chrome/120.0.0.0 Safari/537.36'
)

HEADERS = {
    'Content-Type': 'application/json;charset=UTF-8',
    'Accept': 'application/json, text/plain, */*',
    'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8',
    'Sec-Fetch-Dest': 'empty',
    'Sec-Fetch-Mode': 'cors',
    'Sec-Fetch-Site': 'same-origin',
}

NORMAL_CHECKIN_MESSAGES = (
    "checkin! got",
    "checkin repeats! please try tomorrow",
    "today's observation logged",
)

# 积分自动兑换计划表
EXCHANGE_PLANS = {
    "plan100": {"points": 100, "days": 10},
    "plan200": {"points": 200, "days": 30},
    "plan500": {"points": 500, "days": 100},
}
EXCHANGE_DISABLED_VALUES = ("", "off", "no", "none", "false", "0", "disabled")

CURRENT_SESSION_COOKIES = ('gld:sess', 'gld:sess.sig')
LEGACY_SESSION_COOKIES = ('koa:sess', 'koa:sess.sig')


# ================= 工具函数 =================

def beijing_time():
    """获取当前北京时间字符串"""
    return datetime.now(timezone(timedelta(hours=8))).strftime("%Y-%m-%d %H:%M:%S")


def log(msg):
    """带北京时间戳的控制台日志"""
    print(f"[{beijing_time()} 北京时间] {msg}", flush=True)


def compute_checkin_proof(nonce: str) -> str:
    """计算 SHA-256(nonce + '.glados-observe-v1') 防风控签名"""
    if not nonce:
        return ""
    raw = f"{nonce}.{CHALLENGE_SALT}".encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def extract_cookie(raw: str):
    """提取 Cookie，兼容键值对、多账号及 Cookie-Editor 导出的 JSON 格式"""
    if not raw:
        return None
    raw = raw.strip()
    raw = re.sub(r'^cookie\s*:\s*', '', raw, flags=re.IGNORECASE)
    
    if any(f'{name}=' in raw for name in CURRENT_SESSION_COOKIES + LEGACY_SESSION_COOKIES):
        return raw
        
    if raw.startswith(('{', '[')):
        try:
            parsed = json.loads(raw)
            if isinstance(parsed, list):
                pairs = []
                for item in parsed:
                    if not isinstance(item, dict):
                        continue
                    name = item.get('name')
                    value = item.get('value')
                    if name and value is not None:
                        pairs.append(f'{name}={value}')
                cookie = '; '.join(pairs)
                return cookie if cookie and get_session_cookie_kind(cookie) else None

            token = parsed.get('token') if isinstance(parsed, dict) else None
            return f'koa:sess={token}' if token else None
        except (json.JSONDecodeError, AttributeError, TypeError):
            return None
        
    if raw.count('.') == 2 and '=' not in raw and len(raw) > 50:
        return 'koa:sess=' + raw
        
    return raw


def get_cookie_names(cookie_header):
    names = set()
    for item in cookie_header.split(';'):
        name, separator, _ = item.strip().partition('=')
        if separator and name:
            names.add(name)
    return names


def get_session_cookie_kind(cookie_header):
    names = get_cookie_names(cookie_header)
    if set(CURRENT_SESSION_COOKIES).issubset(names):
        return 'gld'
    if set(LEGACY_SESSION_COOKIES).issubset(names):
        return 'koa'
    return None


def get_cookies():
    raw = os.environ.get("GLADOS_COOKIE", "").strip()
    if not raw:
        log("❌ 未配置环境变量 GLADOS_COOKIE")
        return []

    if raw.lstrip().startswith(('{', '[')):
        cookie = extract_cookie(raw)
        return [cookie] if cookie else []
    
    sep = '\n' if '\n' in raw else '&'
    return [cookie for item in raw.split(sep) if (cookie := extract_cookie(item))]


def get_browser_headers():
    user_agent = os.environ.get("GLADOS_USER_AGENT", "").strip() or DEFAULT_USER_AGENT
    headers = {'User-Agent': user_agent}

    chrome = re.search(r'(?:Chrome|Chromium)/(\d+)', user_agent)
    if chrome:
        major = chrome.group(1)
        platform = 'Windows'
        if 'Macintosh' in user_agent:
            platform = 'macOS'
        elif 'Android' in user_agent:
            platform = 'Android'
        elif 'Linux' in user_agent:
            platform = 'Linux'

        headers.update({
            'Sec-CH-UA': (
                f'"Chromium";v="{major}", '
                f'"Google Chrome";v="{major}", '
                '"Not_A Brand";v="99"'
            ),
            'Sec-CH-UA-Mobile': '?1' if 'Mobile' in user_agent else '?0',
            'Sec-CH-UA-Platform': f'"{platform}"',
        })

    return headers


def is_non_retryable_checkin_result(result):
    if not isinstance(result, dict):
        return False
    code = result.get('code')
    reason = str(result.get('reason', '')).strip().lower()
    message = str(result.get('message', '')).strip().lower()
    return (
        code == -2
        or result.get('http_status') in (401, 403)
        or reason == 'device-mismatch'
        or '没有权限' in message
        or 'permission' in message
        or 'unauthorized' in message
        or 'automated check-in detected' in message
    )


def is_missing_api_response(result):
    return not isinstance(result, dict) or result.get('request_failed') is True


def summarize_checkin_failure(result):
    if not isinstance(result, dict):
        return '未收到有效 API 响应；本次请求失败，今日签到状态未知'

    reason = str(result.get('reason', '')).strip().lower()
    message = str(result.get('message', '')).strip().lower()
    if result.get('request_failed') is True:
        if result.get('invalid_headers') is True:
            label = '请求头格式无效，请检查 Cookie 和 User-Agent 格式'
        elif result.get('invalid_response') is True:
            label = '服务响应格式异常，未收到有效 API 响应'
        else:
            label = '网络或服务暂时异常，未收到有效 API 响应'
        label += '；本次请求失败，今日签到状态未知'
    elif reason == 'device-mismatch':
        label = '服务端拒绝设备校验；请核对会话和 User-Agent 配置'
    elif 'automated check-in detected' in message:
        label = '服务端拒绝自动签到；请核对会话配置，仍失败时联系服务方'
    elif is_non_retryable_checkin_result(result):
        label = '服务端拒绝会话认证或访问'
    else:
        label = '签到失败'

    details = []
    code = result.get('code')
    if type(code) is int and -999 <= code <= 999:
        details.append(f'code={code}')
    status = result.get('http_status')
    if type(status) is int and 100 <= status <= 599:
        details.append(f'http_status={status}')
    if result.get('request_failed') is True and result.get('timed_out') is True:
        details.append('timeout=true')
    if reason in ('device-mismatch', 'http-auth-rejected'):
        details.append(f'reason={reason}')
    return label + (f" [{', '.join(details)}]" if details else '')


def is_normal_checkin_result(result):
    if is_missing_api_response(result):
        return False
    if is_non_retryable_checkin_result(result):
        return False

    message = str(result.get('message', '')).strip().lower()
    if any(marker in message for marker in NORMAL_CHECKIN_MESSAGES):
        return True

    return result.get('code') == 0


def checkin_with_retry(client, attempts=3, delay_seconds=60):
    attempts = max(1, attempts)
    last_result = None

    for attempt in range(1, attempts + 1):
        last_result = client.checkin()
        if is_normal_checkin_result(last_result):
            return last_result, True

        if is_non_retryable_checkin_result(last_result):
            log(f"❌ 签到认证失败，不再重试: {summarize_checkin_failure(last_result)}")
            return last_result, False

        if attempt < attempts:
            log(f"⚠️ 签到第 {attempt}/{attempts} 次失败，{delay_seconds} 秒后重试")
            time.sleep(max(0, delay_seconds))

    return last_result, False


# ================= 核心 GLaDOS 客户端 =================

class GLaDOS:
    def __init__(self, cookie):
        self.cookie = cookie
        self.domain = DOMAINS[0]
        self.email = "?"
        self.left_days = "?"
        self.points = "?"
        self.points_change = "?"
        self.exchange_info = ""
        self.exchange_result = ""
        self.session_cookie_kind = get_session_cookie_kind(cookie)
        if self.session_cookie_kind != 'gld':
            log("⚠️ Cookie 未包含完整的 gld:sess 与 gld:sess.sig，新版接口可能返回权限异常")

    def req(self, method, path, data=None, form=False):
        """带自动多域名故障转移的请求封装"""
        failure = {'request_failed': True, 'reason': 'request-failed'}
        for d in DOMAINS:
            try:
                url = f"{d}{path}"
                h = HEADERS.copy()
                h.update(get_browser_headers())
                h['Cookie'] = self.cookie
                h['Origin'] = d
                h['Referer'] = f"{d}/console/checkin"

                if form:
                    h.pop('Content-Type', None)
                    resp = requests.post(url, headers=h, data=data, timeout=10)
                elif method == 'GET':
                    resp = requests.get(url, headers=h, timeout=10)
                else:
                    resp = requests.post(url, headers=h, json=data, timeout=10)

                if resp.status_code == 200:
                    payload = resp.json()
                    if isinstance(payload, dict):
                        self.domain = d
                        return payload
                    failure['invalid_response'] = True
                    log(f"⚠️ {d} 响应格式异常")
                    continue
                if resp.status_code in (401, 403):
                    return {'http_status': resp.status_code, 'reason': 'http-auth-rejected'}
                failure['http_status'] = resp.status_code
                log(f"⚠️ {d} 返回 HTTP {resp.status_code}")
            except (requests.RequestException, ValueError) as e:
                if isinstance(e, requests.Timeout):
                    failure['timed_out'] = True
                elif isinstance(e, requests.exceptions.InvalidHeader):
                    failure['invalid_headers'] = True
                elif isinstance(e, ValueError):
                    failure['invalid_response'] = True
                log(f"⚠️ {d} 请求失败: {type(e).__name__}")
                continue
        return failure

    def get_status(self):
        """获取账号状态：邮箱、剩余 VIP 天数"""
        res = self.req('GET', '/api/user/status')
        if res and 'data' in res:
            d = res['data']
            self.email = d.get('email', 'Unknown')
            self.left_days = str(d.get('leftDays', '?')).split('.')[0]
            return True
        return False

    def get_points(self):
        """获取总积分余额、最新变动明细与兑换规则进度"""
        res = self.req('GET', '/api/user/points')
        if res and 'points' in res:
            self.points = str(res.get('points', '0')).split('.')[0]
            
            history = res.get('history', [])
            if history:
                last = history[0]
                change = str(last.get('change', '0')).split('.')[0]
                if not change.startswith('-'):
                    change = '+' + change
                self.points_change = change
            
            plans = res.get('plans', {})
            pts = int(float(self.points))
            exchange_lines = []
            for plan_data in plans.values():
                need = int(plan_data.get('points', 0))
                days = plan_data.get('days', '?')
                if pts >= need:
                    exchange_lines.append(f"✅ {need}分→{days}天 (可兑换)")
                else:
                    exchange_lines.append(f"❌ {need}分→{days}天 (差{need-pts}分)")
            self.exchange_info = "<br>".join(exchange_lines)
            return True
        return False

    def solve_challenge(self):
        """获取签到 challenge，等待 2.7 秒后计算 SHA-256 签名通过服务端风控"""
        res = self.req('GET', '/api/user/checkin/challenge')
        if isinstance(res, dict) and res.get('code') == 0 and res.get('nonce'):
            nonce = str(res['nonce'])
            proof = compute_checkin_proof(nonce)
            log(f"🔐 已获取签到 Challenge (nonce={nonce[:8]}...)，模拟真实时长等待 {CHALLENGE_MIN_WAIT_SECONDS} 秒...")
            time.sleep(CHALLENGE_MIN_WAIT_SECONDS)
            return {'nonce': nonce, 'proof': proof}
        log("⚠️ 未能获取签到 Challenge，将回退为基础签到请求")
        return {}

    def checkin(self):
        """发起签到请求（全自动挂载 Proof 验签数据）"""
        payload = {'token': 'glados.cloud'}
        challenge_data = self.solve_challenge()
        if challenge_data:
            host = self.domain.split('//')[-1].strip('/')
            payload['token'] = host or 'glados.cloud'
            payload.update(challenge_data)
        return self.req('POST', '/api/user/checkin', payload)

    def exchange(self, plan):
        """兑换会员天数"""
        return self.req('POST', '/api/user/exchange', {'planType': plan}, form=True)


# ================= 自动兑换 =================

def get_exchange_plan():
    raw = os.environ.get("EXCHANGE_PLAN", "plan500").strip().lower()
    if raw in EXCHANGE_DISABLED_VALUES:
        return None
    if raw in EXCHANGE_PLANS:
        return raw
    log(f"⚠️ EXCHANGE_PLAN 值 '{raw}' 无效，本次跳过自动兑换")
    return None


def auto_exchange(g, plan_id):
    info = EXCHANGE_PLANS[plan_id]
    need, days = info["points"], info["days"]

    try:
        pts = int(float(g.points))
    except (TypeError, ValueError):
        log("⚠️ 积分查询失败，跳过兑换")
        return "⚠️ 兑换跳过(积分查询失败)"

    if pts < need:
        return f"⏭️ 积分不足({pts}/{need})，攒够自动兑换{days}天"

    res = g.exchange(plan_id)
    if res and res.get('code') == 0:
        log(f"🎁 自动兑换成功: {need}分 → +{days}天")
        g.get_status()
        g.get_points()
        return f"🎁 兑换成功 +{days}天 (消耗{need}分)"

    err = res.get('message', 'Failure') if res else "Network Error"
    log(f"⚠️ 自动兑换失败: {err}")
    return f"⚠️ 兑换失败({err})"


# ================= 消息推送 =================

def pushplus(token, title, content):
    """PushPlus 微信推送，自带敏感词脱敏防微信静默拦截"""
    if not token:
        return False
    try:
        url = "https://www.pushplus.plus/send"
        send_title = title
        send_content = content
        
        # 对关键词做脱敏，避免被微信异步消息队列敏感词拦截
        send_title = re.sub(r'glados', '每日自动', send_title, flags=re.IGNORECASE)
        send_content = re.sub(r'glados', 'GLD', send_content, flags=re.IGNORECASE)

        response = requests.post(
            url,
            json={'token': token, 'title': send_title, 'content': send_content, 'template': 'html'},
            timeout=10,
        )
        response.raise_for_status()
        payload = response.json()
        if payload.get('code') not in (None, 0, 200):
            raise RuntimeError(payload.get('msg', f"PushPlus code={payload.get('code')}"))
        serial = payload.get('data', '')
        log(f"✅ PushPlus 微信推送成功" + (f" (流水号: {serial})" if serial else ""))
        return True
    except Exception as e:
        log(f"❌ PushPlus 推送失败: {e}")
        return False


# ================= 主流程 =================

def main():
    log("🚀 GLaDOS 自动签到开始运行...")
    cookies = get_cookies()
    if not cookies:
        return 1

    exchange_plan = get_exchange_plan()
    if exchange_plan:
        plan = EXCHANGE_PLANS[exchange_plan]
        log(f"🎁 自动兑换天数计划已启用: {plan['points']}分 → {plan['days']}天")
    else:
        log("⏭️ 自动兑换未启用")

    results = []
    success_cnt = 0
    exchange_events = 0

    for i, cookie in enumerate(cookies, 1):
        g = GLaDOS(cookie)

        # 1. 签到（带重试）
        attempts = int(os.environ.get("CHECKIN_MAX_ATTEMPTS", "3"))
        delay_seconds = int(os.environ.get("CHECKIN_RETRY_DELAY_SECONDS", "60"))
        res, is_success = checkin_with_retry(g, attempts, delay_seconds)
        msg = res.get('message', 'Success') if is_success else summarize_checkin_failure(res)

        if is_non_retryable_checkin_result(res):
            g.exchange_result = '⏭️ 认证被拒绝，跳过兑换'
        elif is_missing_api_response(res):
            g.exchange_result = '⏭️ 网络或接口异常，跳过积分查询和兑换'
        else:
            # 2. 查询最新天数与积分
            g.get_status()
            g.get_points()

            # 3. 达标自动兑换
            if exchange_plan:
                g.exchange_result = auto_exchange(g, exchange_plan)
                if not g.exchange_result.startswith("⏭️"):
                    exchange_events += 1

        # 4. 控制台日志
        status_icon = "✅" if is_success else "❌"
        log(f"{status_icon} 账号 {i} | 积分: {g.points} | 剩余天数: {g.left_days} | 签到结果: {msg}")

        if is_success:
            success_cnt += 1

        # 5. 生成精美 HTML 推送卡片
        account_label = str(g.email) if g.email != '?' else f'账号 {i}'
        points_label = str(g.points) if g.points != '?' else '未获取'
        change_label = f'({g.points_change})' if g.points_change != '?' else ''
        days_label = f'{g.left_days} 天' if g.left_days != '?' else '未获取'
        
        exchange_line = ""
        if exchange_plan:
            exchange_line = f"""
    <p style="margin:8px 0; color:#000; font-size:16px;"><b>自动兑换:</b> {html.escape(g.exchange_result)}</p>"""

        results.append(f"""
<div style="border:2px solid #333; padding:15px; margin-bottom:15px; border-radius:10px; background:#fff;">
    <h3 style="margin:0 0 15px 0; color:#333; border-bottom:2px solid #333; padding-bottom:8px;">👤 {html.escape(account_label)}</h3>
    <p style="margin:8px 0; color:#000; font-size:16px;"><b>当前总积分:</b> <span style="color:#e74c3c; font-size:22px; font-weight:bold;">{html.escape(points_label)}</span> <span style="color:#27ae60; font-weight:bold;">{html.escape(change_label)}</span></p>
    <p style="margin:8px 0; color:#000; font-size:16px;"><b>剩余天数:</b> <span style="font-weight:bold;">{html.escape(days_label)}</span></p>
    <p style="margin:8px 0; color:#000; font-size:16px;"><b>签到结果:</b> {html.escape(str(msg))}</p>{exchange_line}
    <div style="margin-top:15px; padding:12px; background:#f0f0f0; border-radius:8px; border:1px solid #ccc;">
        <p style="margin:0 0 8px 0; color:#333; font-weight:bold; font-size:15px;">🎁 兑换选项:</p>
        <p style="margin:0; color:#000; font-size:14px; line-height:1.8;">
{g.exchange_info}</p>
    </div>
</div>
""")

    # 6. PushPlus 推送处理（默认 PUSH_LEVEL='all'，确保每天签到成功也能收到微信提醒）
    push_level = os.environ.get("PUSH_LEVEL", "all").lower()

    if push_level == "fail_only" and success_cnt == len(cookies) and exchange_events == 0:
        log("⏭️ 根据 PUSH_LEVEL=fail_only 设置，所有账号签到成功，跳过推送")
        return 0

    ptoken = os.environ.get("PUSHPLUS_TOKEN", "").strip()
    if ptoken:
        outcome = '本次签到成功' if success_cnt == len(cookies) else '本次签到存在异常'
        title = f"GLaDOS签到: {outcome} ({success_cnt}/{len(cookies)})"
        content = "".join(results)
        if success_cnt < len(cookies):
            content += '<p style="color:red;">⚠️ 存在失败账号，请前往官网检查或核对会话状态。</p>'
        content += f"<br><small>执行时间: {beijing_time()} (北京时间)</small>"
        pushplus(ptoken, title, content)
    else:
        log("ℹ️ 未配置 PUSHPLUS_TOKEN，跳过微信推送")

    return 0 if success_cnt == len(cookies) else 1


if __name__ == '__main__':
    sys.exit(main())
