import requests
import os

from pushplus import send_pushplus

# 从环境变量 GLADOS_COOKIE 获取
RAW_COOKIE = os.environ.get("GLADOS_COOKIE", "").strip()

def parse_cookies(cookie_str):
    """解析 Cookie 字符串为字典"""
    cookies = {}
    for item in cookie_str.split(";"):
        item = item.strip()
        if not item:
            continue
        if "=" in item:
            k, v = item.split("=", 1)
            cookies[k.strip()] = v.strip()
    return cookies

def glados_checkin():
    url = "https://glados.one/api/user/checkin"

    headers = {
        "accept": "application/json, text/plain, */*",
        "accept-language": "zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6",
        "content-type": "application/json;charset=UTF-8",
        "origin": "https://glados.one",
        "priority": "u=1, i",
        "sec-ch-ua": '"Microsoft Edge";v="155", "Chromium";v="155", "Not(A:Brand";v="24"',
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": '"Windows"',
        "sec-fetch-dest": "empty",
        "sec-fetch-mode": "cors",
        "sec-fetch-site": "same-origin",
        "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/155.0.0.0 Safari/537.36 Edg/155.0.0.0"
    }

    cookies = parse_cookies(RAW_COOKIE)

    payload = {
        "token": "glados.one"
    }

    try:
        response = requests.post(url, headers=headers, cookies=cookies, json=payload, timeout=30)
        
        # 将返回的结果解析为 JSON
        res_json = response.json()
        print(f"响应内容: {res_json}")
        
        code = res_json.get("code")
        message = res_json.get("message")
        points = res_json.get("points")
        
        print(f"状态码: {code}")
        print(f"Message: {message}")
        if points is not None:
            print(f"获取到的 Points: {points}")
            
        return f"Message: {message},获取到的 Points: {points}"
        
    except Exception as e:
        print(f"请求异常: {e}")

if __name__ == '__main__':
    # 从环境变量中获取 PushPlus Token，如果没有设置则使用默认值
    PUSHPLUS_TOKEN = os.environ.get("PUSHPLUS_TOKEN", "")
    res = glados_checkin()
    send_pushplus(PUSHPLUS_TOKEN, "GLaDOS签到结果", res)
    
