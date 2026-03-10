"""下载 mihomo.exe 内核"""
import sys
import requests
from pathlib import Path

def download_mihomo():
    url = "https://github.com/MetaCubeX/mihomo/releases/download/v1.18.10/mihomo-windows-amd64.exe"
    output_path = Path(__file__).parent.parent / "mihomo.exe"

    try:
        print(f"正在下载 mihomo.exe...")
        response = requests.get(url, timeout=60, allow_redirects=True)
        response.raise_for_status()

        with open(output_path, "wb") as f:
            f.write(response.content)

        print(f"✓ 下载成功: {output_path}")
        return True
    except requests.RequestException as e:
        print(f"✗ 下载失败: {e}")
        return False
    except PermissionError as e:
        print(f"✗ 权限错误: {e}")
        return False
    except Exception as e:
        print(f"✗ 未知错误: {e}")
        return False

if __name__ == "__main__":
    success = download_mihomo()
    sys.exit(0 if success else 1)
