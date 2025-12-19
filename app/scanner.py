from playwright.sync_api import sync_playwright

SUSPICIOUS_JS = [
    "debugger",
    "devtools",
    "eval(",
    "atob(",
    "fromcharcode",
    "setinterval",
    "settimeout",
    "document.location",
    "window.location"
]

PHISHING_KEYWORDS = [
    "login",
    "password",
    "verify",
    "account",
    "microsoft",
    "office"
]

def analyze_url(url: str):
    results = {
        "redirects": [],
        "js_hits": [],
        "phishing_hits": [],
        "verdict": "OK"
    }

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page()

        page.on("framenavigated", lambda frame: results["redirects"].append(frame.url))

        page.goto(url, timeout=20000)
        page.wait_for_timeout(5000)

        html = page.content().lower()

        results["js_hits"] = [x for x in SUSPICIOUS_JS if x in html]
        results["phishing_hits"] = [x for x in PHISHING_KEYWORDS if x in html]

        if results["js_hits"] and results["phishing_hits"]:
            results["verdict"] = "🚨 PROBABILE PHISHING"
        elif results["phishing_hits"]:
            results["verdict"] = "⚠️ SOSPETTO"
        else:
            results["verdict"] = "✅ OK"

        browser.close()

    return results
