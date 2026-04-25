import os
from dotenv import load_dotenv

load_dotenv(os.path.join(os.path.dirname(os.path.abspath(__file__)), '.env'))

# GitHub API
GITHUB_TOKEN = os.getenv('GITHUB_TOKEN', '')
GH_API_BASE = 'https://api.github.com'

# OSS
OSS_ENDPOINT = os.getenv('OSS_ENDPOINT', '')
OSS_BUCKET = os.getenv('OSS_BUCKET', '')
OSS_ACCESS_KEY_ID = os.getenv('OSS_ACCESS_KEY_ID', '')
OSS_ACCESS_KEY_SECRET = os.getenv('OSS_ACCESS_KEY_SECRET', '')
OSS_ENABLED = os.getenv('OSS_ENABLED', 'false').lower() == 'true'
OSS_PREFIX = os.getenv('OSS_PREFIX', 'subot')

# SiliconFlow AI
SILICONFLOW_API_KEY = os.getenv('SILICONFLOW_API_KEY', '')
SILICONFLOW_API_BASE = os.getenv('SILICONFLOW_API_BASE', 'https://api.siliconflow.cn/v1')
SILICONFLOW_MODEL = os.getenv('SILICONFLOW_MODEL', 'stepfun-ai/Step-3.5-Flash')

# Paths
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, 'data')
REPORTS_DIR = os.path.join(BASE_DIR, 'reports')
DB_PATH = os.path.join(DATA_DIR, 'ghsa_intel.db')

# Filter
HOURS_WINDOW = 48
MIN_SEVERITY = ['high', 'critical']

os.makedirs(DATA_DIR, exist_ok=True)
os.makedirs(REPORTS_DIR, exist_ok=True)
