from playwright.sync_api import sync_playwright
import json

def fetch_playwright_json_data(url: str, page_locator: str) -> dict:
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page()
        page.goto(url, wait_until="networkidle")

        raw_text = page.locator(page_locator).inner_text()

        browser.close()

    raw_text = raw_text.strip()

    try:
        return json.loads(raw_text)
    except json.JSONDecodeError as e:
        raise ValueError("Extracted text is not valid JSON") from e