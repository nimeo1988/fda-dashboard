from playwright.sync_api import sync_playwright
import uuid
import os

SUSPICIOUS_JS = [
    'debugger', 'devtools', 'atob(', 'eval(', 'fromcharcode',
    'setinterval', 'settimeout', 'window.location', 'document.location'
]

PHISHING_KEYWORDS = [
    'login', 'password', 'verify', 'microsoft', 'office', 'account'
]

SCREENSHOT_DIR = 'app/static/screenshots'

def scan_url(url: str):
    os.makedirs(SCREENSHOT_DIR, exist_ok=True)
    screenshot_name = f'{uuid.uuid4()}.png'
    screenshot_path = f'{SCREENSHOT_DIR}/{screenshot_name}'

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context()
        page = context.new_page()

        redirects = []
        page.on('framenavigated', lambda f: redirects.append(f.url))

        try:
            page.goto(url, timeout=20000)
            page.wait_for_timeout(5000)
        except:
            pass

        page.screenshot(path=screenshot_path)
        html = page.content().lower()

        js_hits = [s for s in SUSPICIOUS_JS if s in html]
        phishing_hits = [k for k in PHISHING_KEYWORDS if k in html]

        if js_hits and phishing_hits:
            verdict = '🚨 PHISHING'
        elif phishing_hits:
            verdict = '⚠️ SOSPETTO'
        else:
            verdict = '✅ OK'

        browser.close()

    return {
        'verdict': verdict,
        'js_hits': ','.join(js_hits),
        'phishing_hits': ','.join(phishing_hits),
        'redirects': ','.join(set(redirects)),
        'screenshot': screenshot_name
    }
