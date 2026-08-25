#!/usr/bin/env python3
"""
Reverse merged flow (self-contained, high-concurrency):
  Phase 1: Google login  ->  TOTP / Authenticator (2FA) setup
  Phase 2: SAME tab  ->  Instantly OAuth URL  ->  pick account  ->  Continue  ->  Allow

Processes MANY accounts in parallel, each in its own isolated browser session.
The flow steps are identical to the validated single-account run; only the
orchestration around them is concurrent.

Accounts input (any one):
  - ACCOUNTS_JSON env: {"accounts":[{"Email":..,"Password":..},...],"max_parallel":N}
  - CSV file:  python3 reverse_merged.py accounts.csv          (cols: email,password)
  - Single:    python3 reverse_merged.py <email> <password>

Concurrency:
  - MAX_PARALLEL env or max_parallel in JSON (default 5)
  - STAGGER_DELAY env seconds between worker starts (default auto by concurrency)
"""

import os
import sys
import csv
import time
import json
import random
import shutil
import threading
from datetime import datetime
from urllib.parse import urlparse, parse_qs
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
from PIL import Image
from pyzbar.pyzbar import decode

from seleniumbase import Driver
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
INSTANTLY_API_KEY = os.getenv(
    "INSTANTLY_API_KEY",
    "",
).strip()
INSTANTLY_OAUTH_INIT = "https://api.instantly.ai/api/v2/oauth/google/init"
INSTANTLY_DFY_KEY = os.getenv("INSTANTLY_DFY_KEY", "")

TOTP_API_URL = "https://appapi.atozemails.com"
TOTP_API_KEY = os.getenv("TOTP_API_KEY", "")

# Supabase (result reporting into automation_logs.2fa / 2fa_raw_logs, keyed by domain)
SUPABASE_URL = os.getenv("SUPABASE_URL", "")
SUPABASE_KEY = os.getenv("SUPABASE_KEY", "")

AUTHENTICATOR_URL = "https://myaccount.google.com/two-step-verification/authenticator"
LOG_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "reverse_merged.log")

# Concurrency: tuned to run up to 100 accounts in parallel, smoothly.
DEFAULT_MAX_PARALLEL = int(os.getenv("MAX_PARALLEL", "100") or "100")
MAX_PARALLEL_CAP = int(os.getenv("MAX_PARALLEL_CAP", "100") or "100")

# Stability controls for high concurrency
MAX_CONCURRENT_LAUNCHES = int(os.getenv("MAX_CONCURRENT_LAUNCHES", "6") or "6")  # throttle costly browser launches
MIN_FREE_MB = int(os.getenv("MIN_FREE_MB", "1500") or "1500")                    # never launch when RAM is this low
DRIVER_LAUNCH_RETRIES = int(os.getenv("DRIVER_LAUNCH_RETRIES", "4") or "4")
PAGELOAD_TIMEOUT = int(os.getenv("PAGELOAD_TIMEOUT", "90") or "90")              # kill hung page loads
HEADLESS = os.getenv("HEADLESS", "false").lower() in ("1", "true", "yes")

# Only MAX_CONCURRENT_LAUNCHES browsers may be *starting* at any moment (steady
# state can still be up to MAX_PARALLEL). This is the key to a smooth ramp.
_launch_sem = threading.Semaphore(MAX_CONCURRENT_LAUNCHES)
_chromedriver_ready = {"done": False}
_chromedriver_lock = threading.Lock()


def _raise_fd_limit():
    """Bump the open-file-descriptor soft limit for high browser concurrency."""
    try:
        import resource
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        target = min(65535, hard)
        if soft < target:
            resource.setrlimit(resource.RLIMIT_NOFILE, (target, hard))
    except Exception:
        pass


def ensure_chromedriver():
    """Pre-download the UC chromedriver once so 100 workers don't race on first launch."""
    with _chromedriver_lock:
        if _chromedriver_ready["done"]:
            return
        try:
            d = Driver(uc=True, headless=True,
                       chromium_arg="--no-sandbox --disable-dev-shm-usage --disable-gpu")
            d.quit()
            print("[init] chromedriver ready")
        except Exception as e:
            print(f"[init] chromedriver pre-download warning: {e}")
        _chromedriver_ready["done"] = True


def _wait_for_memory(email):
    """Block (up to 2 min) until MIN_FREE_MB RAM is available, so we never OOM the box."""
    try:
        import psutil
    except Exception:
        return
    waited = 0
    while waited < 120:
        avail_mb = psutil.virtual_memory().available / (1024 * 1024)
        if avail_mb >= MIN_FREE_MB:
            return
        if waited == 0:
            print(f"[{_tname()}] low memory ({avail_mb:.0f}MB free) - holding launch for {email}")
        time.sleep(3)
        waited += 3


def _create_driver(user_data_dir, port):
    """Create one isolated UC Chrome with launch retries (handles contention under load)."""
    args = (
        "--no-sandbox --disable-dev-shm-usage --disable-gpu "
        "--disable-software-rasterizer --disable-extensions "
        "--disable-background-networking --disable-renderer-backgrounding "
        "--disable-backgrounding-occluded-windows --disable-features=Translate "
        "--no-first-run --disable-notifications --window-size=1280,800 "
        f"--remote-debugging-port={port}"
    )
    last = None
    for i in range(DRIVER_LAUNCH_RETRIES):
        try:
            return Driver(uc=True, incognito=True, user_data_dir=user_data_dir,
                          headless=HEADLESS, chromium_arg=args)
        except Exception as e:
            last = e
            time.sleep((2 ** i) + random.uniform(0.5, 1.5))
    raise Exception(f"driver launch failed after {DRIVER_LAUNCH_RETRIES} attempts: {last}")

# ---------------------------------------------------------------------------
# Concurrency primitives (shared across worker threads)
# ---------------------------------------------------------------------------
_log_lock = threading.Lock()

# One OAuth URL is fetched from Instantly and shared across workers (cached).
# The Instantly session expires ~10 min after init, so we refresh at < 2 min left.
_oauth_lock = threading.Lock()
_oauth_cache = {"auth_url": None, "expires_at": 0.0}
OAUTH_TTL_SECONDS = 8 * 60          # treat URL as valid for 8 min
OAUTH_REFRESH_MARGIN = 120          # refresh if < 2 min remaining

# Unique remote-debugging port per worker so parallel Chromes never collide.
_port_lock = threading.Lock()
_next_port = {"value": 9600}

# Per-domain locks so concurrent workers never overwrite the same Supabase row.
_domain_locks = {}
_domain_locks_mutex = threading.Lock()


def _get_domain_lock(domain):
    with _domain_locks_mutex:
        if domain not in _domain_locks:
            _domain_locks[domain] = threading.Lock()
        return _domain_locks[domain]


def _tname():
    return threading.current_thread().name


def get_unique_port():
    with _port_lock:
        p = _next_port["value"]
        _next_port["value"] += 1
        return p


# ---------------------------------------------------------------------------
# Logging (thread-safe)
# ---------------------------------------------------------------------------
def log(step, message):
    print(f"\n[{_tname()}][{step}] {message}")
    print("-" * 60)


def log_event(event, email, detail=""):
    line = f"{datetime.now():%Y-%m-%d %H:%M:%S} | {event:<12} | {email}"
    if detail:
        line += f" | {detail}"
    print(f"[{_tname()}] {line}")
    try:
        with _log_lock:
            with open(LOG_FILE, "a", encoding="utf-8") as f:
                f.write(line + "\n")
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Selenium helpers
# ---------------------------------------------------------------------------
def try_find(driver, by, value, timeout=5):
    try:
        return WebDriverWait(driver, timeout).until(
            EC.visibility_of_element_located((by, value))
        )
    except Exception:
        return None


def try_click(driver, by, value, timeout=5):
    el = try_find(driver, by, value, timeout)
    if el:
        try:
            el.click()
            return True
        except Exception:
            try:
                driver.execute_script("arguments[0].click();", el)
                return True
            except Exception:
                pass
    return False


def human_type(element, text, min_delay=0.06, max_delay=0.18):
    element.click()
    time.sleep(random.uniform(0.2, 0.4))
    for idx, char in enumerate(text):
        element.send_keys(char)
        time.sleep(random.uniform(min_delay, max_delay))
        if idx > 0 and idx % random.randint(4, 8) == 0:
            time.sleep(random.uniform(0.1, 0.3))


def find_by_css_list(driver, selectors, timeout=10):
    for sel in selectors:
        el = try_find(driver, By.CSS_SELECTOR, sel, timeout=timeout)
        if el:
            return el, sel
    return None, None


def find_by_text(driver, tag, text, timeout=5):
    try:
        els = WebDriverWait(driver, timeout).until(
            EC.presence_of_all_elements_located((By.TAG_NAME, tag))
        )
        for el in els:
            if el.is_displayed() and text.lower() in (el.text or "").lower():
                return el
    except Exception:
        pass
    return None


def click_by_text(driver, tag, text, timeout=5):
    el = find_by_text(driver, tag, text, timeout)
    if el:
        try:
            el.click()
            return True
        except Exception:
            try:
                driver.execute_script("arguments[0].click();", el)
                return True
            except Exception:
                pass
    return False


# ---------------------------------------------------------------------------
# QR / TOTP / OAuth helpers
# ---------------------------------------------------------------------------
def extract_secret_from_qr(image_path):
    print(f"[{_tname()}][QR Decode] Reading: {image_path}")
    img = Image.open(image_path)
    decoded = decode(img)
    if not decoded:
        raise ValueError("No QR code found in image")
    qr_data = decoded[0].data.decode("utf-8")
    print(f"[{_tname()}] QR Data: {qr_data}")
    parsed = urlparse(qr_data)
    params = parse_qs(parsed.query)
    if "secret" not in params:
        raise ValueError("Secret not found in QR code")
    secret = params["secret"][0]
    print(f"[{_tname()}] Extracted Secret: {secret}")
    return secret


def call_totp_api(api_url, api_key, email, secret):
    url = f"{api_url.rstrip('/')}/api/totp/generate"
    headers = {"x-api-key": api_key, "Content-Type": "application/json"}
    payload = {"email": email, "secret": secret}
    print(f"[{_tname()}][API] POST {url}")
    response = requests.post(url, json=payload, headers=headers, timeout=30)
    print(f"[{_tname()}] Status: {response.status_code}")
    if response.status_code != 200:
        raise Exception(f"API Error {response.status_code}: {response.text}")
    totp_code = response.json().get("totp_code")
    if not totp_code:
        raise Exception("No totp_code in API response")
    print(f"[{_tname()}] TOTP Code: {totp_code}")
    return totp_code


def call_totp_bulk(email, api_url=TOTP_API_URL, api_key=TOTP_API_KEY):
    """Re-run helper: fetch the CURRENT code for an already-enrolled email.
    Reads the stored secret from the DB by email (no secret sent). Handles both
    {'results':[...]} and bare-object responses."""
    url = f"{api_url.rstrip('/')}/api/totp/bulk"
    headers = {"x-api-key": api_key, "Content-Type": "application/json"}
    print(f"[{_tname()}][API] POST {url} (bulk) for {email}")
    r = requests.post(url, json={"emails": [email]}, headers=headers, timeout=30)
    if r.status_code != 200:
        raise Exception(f"bulk API error {r.status_code}: {r.text}")
    data = r.json()
    if isinstance(data, dict) and "results" in data:
        entries = data["results"]
    elif isinstance(data, list):
        entries = data
    else:
        entries = [data]
    # prefer the exact-email match, else first entry that has a code
    for e in entries:
        if str(e.get("email", "")).lower() == email.lower() and e.get("totp_code"):
            return e.get("totp_code")
    for e in entries:
        if e.get("totp_code"):
            return e.get("totp_code")
    # surface a stored-secret-not-found error if present
    err = next((e.get("error") for e in entries if e.get("error")), "no totp_code returned")
    raise Exception(f"bulk API: {err}")


def mark_2fa_added(email, api_url=TOTP_API_URL, api_key=TOTP_API_KEY):
    """Flag the account as 2FA-complete in the accounts DB (idempotent).
    Called after 2FA is confirmed done. Non-fatal: a failure here does not fail
    the account, because the 2FA setup itself already succeeded."""
    url = f"{api_url.rstrip('/')}/api/accounts/2fa"
    headers = {"x-api-key": api_key, "Content-Type": "application/json"}
    try:
        r = requests.post(url, json={"email": email}, headers=headers, timeout=20)
        if r.status_code == 200:
            data = r.json()
            log_event("2FA_MARK", email, f"is_2fa_added={data.get('is_2fa_added')}")
            return True
        log_event("2FA_MARK_ERR", email, f"HTTP {r.status_code}: {r.text[:120]}")
        return False
    except Exception as e:
        log_event("2FA_MARK_ERR", email, f"Exception: {e}")
        return False


def _fetch_oauth_url_raw():
    headers = {
        "Authorization": f"Bearer {INSTANTLY_API_KEY}",
        "Content-Type": "application/json",
        "x-dfy-internal-api-key": INSTANTLY_DFY_KEY,
    }
    last_err = None
    for attempt in range(5):
        try:
            r = requests.post(INSTANTLY_OAUTH_INIT, json={}, headers=headers, timeout=20)
            r.raise_for_status()
            url = r.json().get("auth_url")
            if not url:
                raise Exception("auth_url missing in Instantly API response")
            return url
        except Exception as e:
            last_err = e
            time.sleep((2 ** attempt) + random.uniform(0.5, 1.5))
    raise Exception(f"Failed to get OAuth URL after 5 attempts: {last_err}")


def get_oauth_url():
    """Thread-safe cached OAuth URL shared across all workers; refreshes near expiry."""
    now = time.time()
    with _oauth_lock:
        remaining = _oauth_cache["expires_at"] - now
        if _oauth_cache["auth_url"] and remaining > OAUTH_REFRESH_MARGIN:
            return _oauth_cache["auth_url"]
        url = _fetch_oauth_url_raw()
        _oauth_cache["auth_url"] = url
        _oauth_cache["expires_at"] = time.time() + OAUTH_TTL_SECONDS
        print(f"[{_tname()}][OAuth] fetched new shared OAuth URL (valid {OAUTH_TTL_SECONDS//60} min)")
        return url


# ---------------------------------------------------------------------------
# Supabase result reporter (thread-safe, per-domain)
# ---------------------------------------------------------------------------
def update_supabase_2fa(email, success):
    """
    Append this user's result to 2fa_raw_logs array for the domain row.
    Set 2fa = 'Done' only if every entry in the array is Success, else 'Failed'.
    Per-domain lock so concurrent workers never overwrite each other.
    """
    try:
        domain = email.split("@")[-1].strip().lower()
        row_url = f"{SUPABASE_URL}/rest/v1/automation_logs?domain=eq.{domain}"
        headers_read = {
            "apikey": SUPABASE_KEY,
            "Authorization": f"Bearer {SUPABASE_KEY}",
            "Accept": "application/json",
        }
        headers_write = {
            "apikey": SUPABASE_KEY,
            "Authorization": f"Bearer {SUPABASE_KEY}",
            "Content-Type": "application/json",
            "Prefer": "return=minimal",
        }

        lock = _get_domain_lock(domain)
        with lock:
            get_resp = requests.get(f"{row_url}&select=2fa_raw_logs", headers=headers_read, timeout=15)
            current_array = []
            if get_resp.status_code == 200:
                rows = get_resp.json()
                if rows and rows[0].get("2fa_raw_logs"):
                    existing = rows[0]["2fa_raw_logs"]
                    if isinstance(existing, list):
                        current_array = existing
                    elif isinstance(existing, dict):
                        current_array = [existing]
            else:
                print(f"[{_tname()}][Supabase] GET failed domain={domain} HTTP {get_resp.status_code}")

            current_array.append({"email": email, "status": "Success" if success else "Failed"})
            all_success = all(e.get("status") == "Success" for e in current_array)
            fa_status = "Done" if all_success else "Failed"

            patch_resp = requests.patch(
                row_url,
                json={"2fa": fa_status, "2fa_raw_logs": current_array},
                headers=headers_write,
                timeout=15,
            )
            if patch_resp.status_code in (200, 204):
                log_event("SUPABASE", email, f"domain={domain} | 2fa={fa_status} | entries={len(current_array)}")
            else:
                log_event("SUPABASE_ERR", email, f"domain={domain} | HTTP {patch_resp.status_code}")
    except Exception as e:
        log_event("SUPABASE_ERR", email, f"Exception: {e}")


# ---------------------------------------------------------------------------
# Phase 1 — login + TOTP/2FA   (flow identical to validated run)
# ---------------------------------------------------------------------------
def handle_2fa_challenge(driver, email):
    """If Google asks for a 2-step code (already-enrolled account), fetch the current
    code from the stored secret via the TOTP /bulk API and submit it.
    Returns True if a challenge was detected + handled, else False."""
    cur = driver.current_url

    # Only relevant if we're on a 2-step challenge page.
    if "challenge" not in cur:
        return False

    # If a method chooser is shown, pick "Google Authenticator" first.
    code_input, _ = find_by_css_list(
        driver, ['input[name="totpPin"]', 'input#totpPin', 'input[type="tel"]'], timeout=3
    )
    if not code_input:
        if (click_by_text(driver, "div", "Google Authenticator")
                or click_by_text(driver, "li", "Google Authenticator")
                or click_by_text(driver, "div", "authenticator")):
            time.sleep(2)
        code_input, _ = find_by_css_list(
            driver, ['input[name="totpPin"]', 'input#totpPin', 'input[type="tel"]'], timeout=3
        )
    if not code_input:
        return False

    log("P1-CHALLENGE", f"2-step code prompt detected for {email} - using stored secret")
    code = call_totp_bulk(email)
    if not code:
        raise Exception("2FA challenge but no code returned from bulk API")
    human_type(code_input, code)
    time.sleep(0.6)
    if not try_click(driver, By.ID, "totpNext", timeout=4):
        if not click_by_text(driver, "button", "Next"):
            code_input.send_keys(Keys.RETURN)
    time.sleep(random.uniform(4, 6))
    log_event("2FA_CHALLENGE", email, f"entered code {code} from stored secret | url={driver.current_url[:60]}")
    return True


def login_google(driver, email, password):
    log("P1-LOGIN", f"Google login (email/password) for {email}")
    driver.get(AUTHENTICATOR_URL)
    time.sleep(random.uniform(3, 5))
    print(f"[{_tname()}] URL after nav: {driver.current_url}")

    email_el, _ = find_by_css_list(
        driver,
        ["#identifierId", 'input[type="email"]', 'input[name="identifier"]'],
        timeout=20,
    )
    if not email_el:
        raise Exception("Email input not found at login")
    human_type(email_el, email)
    time.sleep(0.6)
    if not try_click(driver, By.ID, "identifierNext", timeout=5):
        if not click_by_text(driver, "button", "Next"):
            email_el.send_keys(Keys.RETURN)
    time.sleep(random.uniform(4, 6))

    if "rejected" in driver.current_url:
        raise Exception("Google rejected sign-in (bot detection)")

    pw_el, _ = find_by_css_list(
        driver,
        ['input[type="password"]', 'input[name="Passwd"]'],
        timeout=20,
    )
    if not pw_el:
        raise Exception("Password input not found at login")
    human_type(pw_el, password)
    time.sleep(0.6)
    if not try_click(driver, By.ID, "passwordNext", timeout=5):
        if not click_by_text(driver, "button", "Next"):
            pw_el.send_keys(Keys.RETURN)
    time.sleep(random.uniform(5, 7))
    print(f"[{_tname()}] URL after password: {driver.current_url}")

    # Already-enrolled accounts hit a 2-step code prompt here instead of the
    # setup page -> answer it from the stored secret and skip setup later.
    already_enrolled = handle_2fa_challenge(driver, email)

    print(f"[{_tname()}] URL after login: {driver.current_url}")
    log_event("LOGIN", email, f"login submitted | already_enrolled={already_enrolled}")
    return already_enrolled


def setup_2fa(driver, email):
    worker_id = threading.get_ident()
    shot = f"/tmp/qr_reverse_{worker_id}.png"
    try:
        log("P1-2FA", "Set up Authenticator + capture QR")
        driver.get(AUTHENTICATOR_URL)
        time.sleep(random.uniform(3, 5))

        clicked = (
            try_click(driver, By.CSS_SELECTOR, 'button[aria-label*="Set up authenticator"]', timeout=6)
            or click_by_text(driver, "button", "Set up authenticator")
            or click_by_text(driver, "span", "Set up authenticator")
            or click_by_text(driver, "button", "Set up")
        )
        print(f"[{_tname()}][2FA] set-up clicked={clicked}")
        time.sleep(random.uniform(4, 6))  # wait for QR dialog to render

        qr_el = None
        for attempt in range(6):
            for sel in [
                'div[role="dialog"] img',
                'img[alt*="QR"]',
                'img[alt*="code"]',
                'c-wiz img',
                'img[src^="data:image"]',
            ]:
                qr_el = try_find(driver, By.CSS_SELECTOR, sel, timeout=2)
                if qr_el:
                    print(f"[{_tname()}][2FA] QR element found: {sel}")
                    break
            if qr_el:
                break
            print(f"[{_tname()}][2FA] QR not found yet (attempt {attempt + 1}/6), waiting...")
            time.sleep(2)

        if qr_el:
            qr_el.screenshot(shot)
        else:
            print(f"[{_tname()}][2FA] QR element not found - full page screenshot fallback")
            driver.save_screenshot(shot)

        secret = extract_secret_from_qr(shot)
        log_event("SECRET", email, f"secret={secret}")

        totp = call_totp_api(TOTP_API_URL, TOTP_API_KEY, email, secret)
        log_event("TOTP", email, f"totp={totp}")

        click_by_text(driver, "button", "Next") or try_click(
            driver, By.CSS_SELECTOR, 'div[role="dialog"] button', timeout=3
        )
        time.sleep(2)

        code_el, _ = find_by_css_list(
            driver,
            ['input[type="tel"]', 'div[role="dialog"] input', 'input[type="text"]', 'input[name*="code"]'],
            timeout=10,
        )
        if not code_el:
            raise Exception("TOTP input not found")
        human_type(code_el, totp)
        time.sleep(0.7)

        if not (click_by_text(driver, "button", "Verify") or click_by_text(driver, "button", "Confirm")):
            code_el.send_keys(Keys.RETURN)
        time.sleep(random.uniform(3, 5))

        # optional Turn on / Done
        turn_on = try_find(driver, By.CSS_SELECTOR, 'a[aria-label="Turn on"]', timeout=3)
        if turn_on:
            try:
                turn_on.click()
                time.sleep(3)
                tob = try_find(driver, By.CSS_SELECTOR, 'button[aria-label="Turn on 2-Step Verification"]', timeout=4) \
                    or find_by_text(driver, "button", "Turn on 2-Step Verification", timeout=4)
                if tob:
                    try:
                        tob.click()
                    except Exception:
                        driver.execute_script("arguments[0].click();", tob)
                    time.sleep(3)
            except Exception as e:
                print(f"[{_tname()}][2FA] turn-on flow: {e}")
        if click_by_text(driver, "button", "Done") or click_by_text(driver, "a", "Done"):
            print(f"[{_tname()}][2FA] clicked Done")
        time.sleep(2)

        return {"status": "success", "email": email, "secret": secret, "totp_code": totp}
    except Exception as e:
        try:
            driver.save_screenshot(f"/tmp/debug_reverse_2fa_{worker_id}.png")
        except Exception:
            pass
        return {"status": "error", "email": email, "error": str(e)}
    finally:
        try:
            os.remove(shot)
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Phase 2 — same session -> Instantly OAuth   (flow identical to validated run)
# ---------------------------------------------------------------------------
def authorize_instantly(driver, email):
    log("P2-OAUTH", "Navigate to Instantly OAuth URL, pick account, Continue + Allow (same session)")
    auth_url = get_oauth_url()
    print(f"[{_tname()}][OAUTH] auth_url: {auth_url[:80]}...")
    driver.get(auth_url)
    time.sleep(random.uniform(4, 6))
    print(f"[{_tname()}][OAUTH] URL: {driver.current_url}")

    # STEP 1 - Account chooser: click the tile for THIS email
    picked = (
        try_click(driver, By.CSS_SELECTOR, f'div[data-identifier="{email}"]', timeout=6)
        or try_click(driver, By.CSS_SELECTOR, f'[data-identifier="{email}"]', timeout=3)
        or try_click(driver, By.CSS_SELECTOR, f'[data-email="{email}"]', timeout=3)
        or try_click(driver, By.XPATH, f'//*[@data-identifier="{email}"]', timeout=3)
        or try_click(driver, By.XPATH, f'//div[contains(text(),"{email}")]/ancestor::*[@role="link"][1]', timeout=3)
        or try_click(driver, By.XPATH, f'//li[.//*[contains(text(),"{email}")]]', timeout=3)
        or click_by_text(driver, "div", email)
    )
    print(f"[{_tname()}][OAUTH] account picked={picked}")
    time.sleep(random.uniform(3, 5))
    print(f"[{_tname()}][OAUTH] URL after pick: {driver.current_url}")

    # 'I understand' (rare)
    try_click(driver, By.XPATH, '//input[@id="confirm"]', timeout=3)

    # STEP 2 - Consent: click Continue / Allow until redirected back to Instantly host
    def _redirected_to_instantly():
        return urlparse(driver.current_url).netloc.lower().endswith("instantly.ai")

    cont = False
    allow = False
    deadline = time.time() + 50
    while time.time() < deadline:
        if _redirected_to_instantly():
            break
        if click_by_text(driver, "button", "Allow", timeout=2):
            allow = True
            time.sleep(2)
            continue
        if click_by_text(driver, "button", "Continue", timeout=2):
            cont = True
            time.sleep(2)
            continue
        time.sleep(1.5)

    final_url = driver.current_url
    granted = _redirected_to_instantly()
    print(f"[{_tname()}][OAUTH] continue={cont} allow={allow} | final_url={final_url}")
    log_event("OAUTH", email, f"continue={cont} allow={allow} granted={granted}")
    return {
        "status": "success" if granted else "partial",
        "email": email,
        "picked": bool(picked),
        "continue": cont,
        "allow": allow,
        "final_url": final_url,
    }


# ---------------------------------------------------------------------------
# Per-account worker (isolated browser)   flow identical to validated run
# ---------------------------------------------------------------------------
def run_one(email, password, max_retries=10):
    start = time.time()
    for attempt in range(1, max_retries + 1):
        user_data_dir = f"/tmp/rev_{os.getpid()}_{threading.get_ident()}_{random.randint(1000, 9999)}"
        port = get_unique_port()
        driver = None
        try:
            log_event("START", email, f"attempt {attempt}/{max_retries} | port={port}")
            # Throttle the expensive launch phase: at most MAX_CONCURRENT_LAUNCHES
            # browsers start at once, and never launch when RAM is low.
            with _launch_sem:
                _wait_for_memory(email)
                driver = _create_driver(user_data_dir, port)
            try:
                driver.set_page_load_timeout(PAGELOAD_TIMEOUT)
                driver.set_script_timeout(PAGELOAD_TIMEOUT)
            except Exception:
                pass
            time.sleep(1)

            print("=" * 60)
            print(f"[{_tname()}] REVERSE FLOW | {email}")
            print(f"[{_tname()}] Order: (1) LOGIN + TOTP/2FA -> (2) same tab OAuth upload")
            print("=" * 60)

            # PHASE 1 — login (+ TOTP/2FA setup only on first-time accounts)
            already_enrolled = login_google(driver, email, password)
            if already_enrolled:
                # Re-run: 2FA already set up + code answered from stored secret -> skip setup
                print(f"[{_tname()}] Account already enrolled - skipping 2FA setup, going to OAuth")
                r1 = {"status": "success", "email": email, "note": "already_enrolled_skip_setup"}
            else:
                r1 = setup_2fa(driver, email)
            print(f"[{_tname()}] PHASE1_RESULT:: {r1}")
            print(f"STATUS_EVENT::{email}::2fa_{r1.get('status')}::secret={r1.get('secret', '')}")
            if r1.get("status") != "success":
                raise Exception(f"Phase1 (2FA) failed: {r1.get('error')}")

            # 2FA is confirmed done -> flag the account as 2FA-complete (idempotent)
            mark_2fa_added(email)

            # PHASE 2 — same tab -> Instantly OAuth
            r2 = authorize_instantly(driver, email)
            print(f"[{_tname()}] PHASE2_RESULT:: {r2}")
            print(f"STATUS_EVENT::{email}::oauth_{r2.get('status')}::allow={r2.get('allow')}")

            duration = round(time.time() - start, 1)
            ok = r2.get("status") == "success"
            update_supabase_2fa(email, success=ok)
            log_event("DONE" if ok else "PARTIAL", email, f"phase2={r2.get('status')} | {duration}s")
            return {"email": email, "phase1": r1, "phase2": r2,
                    "status": "success" if ok else "partial", "duration": duration}

        except Exception as e:
            print(f"[{_tname()}] Error processing {email} (attempt {attempt}): {e}")
            try:
                if driver:
                    driver.save_screenshot(f"/tmp/debug_reverse_main_{threading.get_ident()}.png")
            except Exception:
                pass
            log_event("ERROR", email, f"attempt {attempt}: {e}")
            if attempt >= max_retries:
                update_supabase_2fa(email, success=False)
                print(f"STATUS_EVENT::{email}::error::{e}")
                return {"email": email, "status": "error", "error": str(e),
                        "duration": round(time.time() - start, 1)}
            time.sleep(random.uniform(3, 6))  # backoff before retry
        finally:
            if driver:
                try:
                    driver.quit()
                except Exception:
                    pass
            shutil.rmtree(user_data_dir, ignore_errors=True)


# ---------------------------------------------------------------------------
# Parallel orchestrator
# ---------------------------------------------------------------------------
def auto_stagger(max_parallel):
    # The launch semaphore already throttles real browser starts, so the stagger
    # between task submissions can stay small.
    if max_parallel >= 40:
        return 1.0
    if max_parallel >= 20:
        return 1.5
    if max_parallel >= 10:
        return 2.0
    return 3.0


def process_all(accounts, max_parallel, stagger, max_retries=1):
    total = len(accounts)
    print(f"\n{'='*60}")
    print(f" REVERSE MERGED FLOW  |  {total} account(s)")
    print(f" MAX_PARALLEL={max_parallel}  LAUNCH_THROTTLE={MAX_CONCURRENT_LAUNCHES}  "
          f"STAGGER={stagger}s  retries={max_retries}  headless={HEADLESS}")
    print(f"{'='*60}\n")

    _raise_fd_limit()
    ensure_chromedriver()  # download the driver once before workers spin up

    results = []
    results_lock = threading.Lock()

    with ThreadPoolExecutor(max_workers=max_parallel, thread_name_prefix="acct") as pool:
        futures = {}
        for idx, acc in enumerate(accounts):
            email = acc["email"]
            password = acc["password"]
            fut = pool.submit(run_one, email, password, max_retries)
            futures[fut] = email
            # stagger worker starts to avoid resource spikes on browser launch
            if idx < total - 1:
                time.sleep(stagger)

        for fut in as_completed(futures):
            email = futures[fut]
            try:
                res = fut.result()
            except Exception as e:
                res = {"email": email, "status": "error", "error": str(e)}
            with results_lock:
                results.append(res)
            print(f"[MAIN] finished {email}: {res.get('status')}")

    # Summary
    ok = sum(1 for r in results if r.get("status") == "success")
    part = sum(1 for r in results if r.get("status") == "partial")
    err = sum(1 for r in results if r.get("status") == "error")
    print(f"\n{'='*60}")
    print(f" SUMMARY  |  total={total}  success={ok}  partial={part}  error={err}")
    print(f"{'='*60}")
    for r in results:
        print(f"  {r.get('status','?'):<8} {r.get('email','')}  "
              f"{('- ' + r.get('error','')) if r.get('status')=='error' else ''}")
    print(f"{'='*60}\n")
    log_event("SUMMARY", "-", f"total={total} success={ok} partial={part} error={err}")
    return results


# ---------------------------------------------------------------------------
# Account loading
# ---------------------------------------------------------------------------
def _norm_account(d):
    email = (d.get("Email") or d.get("email") or "").strip()
    password = (d.get("Password") or d.get("password") or "").strip()
    return {"email": email, "password": password}


def load_accounts_and_config():
    """Returns (accounts_list, max_parallel). Accepts ACCOUNTS_JSON, CSV path, or 2 args."""
    data = os.getenv("ACCOUNTS_JSON", "").strip()
    if data:
        payload = json.loads(data)
        raw = payload.get("accounts") or ([payload] if payload.get("Email") or payload.get("email") else [])
        accounts = [_norm_account(a) for a in raw]
        mp = int(payload.get("max_parallel") or payload.get("max_parallel_tabs") or DEFAULT_MAX_PARALLEL)
        return [a for a in accounts if a["email"] and a["password"]], mp

    args = [a for a in sys.argv[1:]]
    if len(args) == 1 and os.path.isfile(args[0]):
        accounts = []
        with open(args[0], newline="", encoding="utf-8") as f:
            reader = csv.reader(f)
            rows = list(reader)
        # skip header if it looks like one
        if rows and rows[0] and "@" not in rows[0][0]:
            rows = rows[1:]
        for row in rows:
            if len(row) >= 2 and row[0].strip():
                accounts.append({"email": row[0].strip(), "password": row[1].strip()})
        return accounts, DEFAULT_MAX_PARALLEL

    if len(args) >= 2:
        return [{"email": args[0].strip(), "password": args[1].strip()}], DEFAULT_MAX_PARALLEL

    return [], DEFAULT_MAX_PARALLEL


def main():
    _raise_fd_limit()
    accounts, max_parallel = load_accounts_and_config()
    if not accounts:
        print("No accounts. Provide ACCOUNTS_JSON env, a CSV path, or: reverse_merged.py <email> <password>")
        sys.exit(1)

    max_parallel = max(1, min(max_parallel, len(accounts), MAX_PARALLEL_CAP))
    stagger = float(os.getenv("STAGGER_DELAY", "") or auto_stagger(max_parallel))
    max_retries = int(os.getenv("MAX_RETRIES", "10") or "10")

    process_all(accounts, max_parallel, stagger, max_retries)


if __name__ == "__main__":
    main()
