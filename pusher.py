"""Pusher: 上传 HTML 到 OSS"""
import oss2
from config import (OSS_ENDPOINT, OSS_BUCKET, OSS_ACCESS_KEY_ID, 
                    OSS_ACCESS_KEY_SECRET, OSS_ENABLED, OSS_PREFIX)

def upload_to_oss(local_path: str, remote_name: str) -> str:
    """上传文件到 OSS，返回公开 URL"""
    if not OSS_ENABLED:
        print("[pusher] OSS disabled, skipping upload")
        return ''
    
    try:
        auth = oss2.Auth(OSS_ACCESS_KEY_ID, OSS_ACCESS_KEY_SECRET)
        # 用 http + 较大超时
        bucket = oss2.Bucket(
            auth, f'http://{OSS_ENDPOINT}', OSS_BUCKET,
            connect_timeout=30,
        )
        
        remote_path = f'{OSS_PREFIX}/{remote_name}'
        with open(local_path, 'rb') as f:
            result = bucket.put_object(remote_path, f.read(), headers={
                'Content-Type': 'text/html; charset=utf-8',
                'Cache-Control': 'no-cache',
            })
        
        if result.status == 200:
            url = f'https://{OSS_BUCKET}.{OSS_ENDPOINT}/{remote_path}'
            print(f"[pusher] Uploaded: {url}")
            return url
        else:
            print(f"[pusher] Upload failed: status={result.status}")
            return ''
        
    except Exception as e:
        print(f"[pusher] OSS upload error: {e}")
        return ''
