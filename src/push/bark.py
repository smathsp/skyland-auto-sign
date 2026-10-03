"""Bark notifications via POST JSON; the device key stays out of URLs."""
import logging
import os
from datetime import date
from urllib.parse import urlsplit

import requests


def push_bark(all_logs: list[str]) -> bool:
    key = os.environ.get('BARK_KEY', '').strip()
    if not key:
        return True

    server = os.environ.get('BARK_SERVER', '').strip() or 'https://api.day.app'
    try:
        parsed = urlsplit(server)
        if parsed.scheme not in ('http', 'https') or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
            logging.error('BARK_SERVER 应为 Bark 服务地址，如 https://api.day.app')
            return False
        response = requests.post(
            server.rstrip('/') + '/push',
            json={
                'device_key': key,
                'title': f'森空岛自动签到结果 - {date.today():%Y-%m-%d}',
                'body': '\n'.join(all_logs) if all_logs else '今日无可用账号或无输出',
                'group': '森空岛签到',
            },
            timeout=(10, 30),
            allow_redirects=False,
        )
        if response.status_code != 200:
            logging.error('Bark 推送失败，HTTP %s', response.status_code)
            return False
        if response.json().get('code') != 200:
            logging.error('Bark 推送失败，服务端未返回成功状态')
            return False
    except Exception as ex:
        logging.error('Bark 推送失败：%s', type(ex).__name__)
        return False

    logging.info('Bark 推送成功')
    return True
