import requests


def fetch_webhook(target_url):
    # Server-side request forgery (SSRF)
    resp = requests.get(target_url, timeout=5)
    return resp.text

