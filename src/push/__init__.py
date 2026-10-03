import os
from configparser import ConfigParser
from push.bark import push_bark

def load_config_to_env():
    """从config.ini文件加载配置到环境变量"""
    config = ConfigParser()
    
    # 尝试读取同目录下的config.ini文件
    config_path = os.path.join(os.path.dirname(__file__), 'config.ini')
    if os.path.exists(config_path):
        config.read(config_path, encoding='utf-8')
        
        # 遍历配置文件中的所有section和option，添加到环境变量
        for section_name in config.sections():
            for option in config.options(section_name):
                value = config.get(section_name, option)
                # 将配置项添加到环境变量中
                env_key = option.upper()  # 转换为大写作为环境变量名
                if value and not os.environ.get(env_key):
                    os.environ[env_key] = value

# 加载配置到环境变量
load_config_to_env()

def push(all_logs: list[str]):
    return push_bark(all_logs)
