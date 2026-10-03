import logging
import os
import time
from datetime import date
from urllib.parse import urlsplit

import requests

import push
from skyland import start

exit_when_fail_env = os.environ.get('EXIT_WHEN_FAIL')
use_proxy = os.environ.get('USE_PROXY')

def config_logger():
    current_date = date.today().strftime('%Y-%m-%d')
    if not os.path.exists('logs'):
        os.mkdir('logs')
    logger = logging.getLogger()

    file_handler = logging.FileHandler(f'./logs/{current_date}.log', encoding='utf-8')
    logger.addHandler(file_handler)
    logger.setLevel(logging.DEBUG)
    file_handler.setLevel(logging.INFO)
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    file_handler.setFormatter(formatter)

    console_handler = logging.StreamHandler()
    # console_formatter = logging.Formatter('%(message)s')
    # console_handler.setFormatter(console_formatter)
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

    _get = requests.get
    _post = requests.post

    def get(*args, **kwargs):
        if use_proxy:
            kwargs.update({
                'proxies': {
                    'https': 'http://localhost:8000',
                },
                'verify': False
            })
        response = _get(*args, **kwargs)
        logger.debug('GET %s - %s', urlsplit(args[0]).hostname, response.status_code)
        return response

    def post(*args, **kwargs):
        if use_proxy:
            kwargs.update({
                'proxies': {
                    'https': 'http://localhost:8000',
                },
                'verify': False
            })
        response = _post(*args, **kwargs)
        logger.debug('POST %s - %s', urlsplit(args[0]).hostname, response.status_code)
        return response

    # 替换 requests 中的方法
    requests.get = get
    requests.post = post


def main():
    config_logger()

    print('本项目源代码仓库：https://github.com/smathsp/skyland-auto-sign')
    logging.info('=========starting==========')
    start_time = time.time()
    success, all_logs = start()
    push.push(all_logs)
    end_time = time.time()
    logging.info(f'complete with {(end_time - start_time) * 1000} ms')
    logging.info('===========ending============')

    logging.info(f'exit_when_fail_env: {exit_when_fail_env}, success: {success}')
    if (exit_when_fail_env == "on") and not success:
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
