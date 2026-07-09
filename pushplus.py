import requests


def send_pushplus(token, title, content, template="html"):
    """
    使用 pushplus 推送消息
    
    :param token: 您的 pushplus token (在官网获取)
    :param title: 推送的消息标题
    :param content: 推送的消息具体内容
    :param template: 消息模板，支持 html, txt, json, markdown 等，默认为 html
    :return: 成功返回 True，失败返回 False
    """
    url = "http://www.pushplus.plus/send"
    payload = {
        "token": token,
        "title": title,
        "content": content,
        "template": template
    }
    
    try:
        # 推荐使用 POST 发送 JSON 数据，避免由于内容过长导致 GET 请求超限
        response = requests.post(url, json=payload, timeout=10)
        response.raise_for_status()  # 检查 HTTP 状态码
        
        res_json = response.json()
        if res_json.get("code") == 200:
            print(f"✅ 推送成功！提示: {res_json.get('msg')}")
            return True
        else:
            print(f"❌ 推送失败！错误信息: {res_json.get('msg')}")
            return False
            
    except Exception as e:
        print(f"⚠️ 推送发生异常: {e}")
        return False

