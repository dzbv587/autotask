import requests
import os

from pushplus import send_pushplus

# 从环境变量中获取 Cookie，如果没有设置则使用默认值
KOA_SESS = os.environ.get("GLADOS_KOA_SESS", "")
KOA_SESS_SIG = os.environ.get("GLADOS_KOA_SESS_SIG", "")

def glados_checkin():
    url = 'https://glados.one/api/user/checkin'

    headers = {
        'accept': 'application/json, text/plain, */*',
        'accept-language': 'zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6',
        'content-type': 'application/json;charset=UTF-8',
        'origin': 'https://glados.one',
        'priority': 'u=1, i',
        'sec-ch-ua': '"Not;A=Brand";v="8", "Chromium";v="150", "Microsoft Edge";v="150"',
        'sec-ch-ua-mobile': '?0',
        'sec-ch-ua-platform': '"Windows"',
        'sec-fetch-dest': 'empty',
        'sec-fetch-mode': 'cors',
        'sec-fetch-site': 'same-origin',
        'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36 Edg/150.0.0.0'
    }

    cookies = {
        'koa:sess': KOA_SESS,
        'koa:sess.sig': KOA_SESS_SIG
    }

    data = {
        'token': 'glados.one'
    }

    try:
        response = requests.post(url, headers=headers, cookies=cookies, json=data)
        
        # 将返回的结果解析为 JSON
        res_json = response.json()
        
        # 提取并打印 point
        points = res_json.get("points")
        message = res_json.get("message")
        
        print(f"Message: {message}")
        print(f"获取到的 Points: {points}")
        return f"Message: {message},获取到的 Points: {points}"
        
    except Exception as e:
        print(f"请求异常: {e}")

if __name__ == '__main__':
    # 从环境变量中获取 PushPlus Token，如果没有设置则使用默认值
    PUSHPLUS_TOKEN = os.environ.get("PUSHPLUS_TOKEN", "")
    res = glados_checkin()
    send_pushplus(PUSHPLUS_TOKEN, "GLaDOS签到结果", res)
    