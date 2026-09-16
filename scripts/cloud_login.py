"""Normal QR login in a fresh cloud browser; never imports desktop cookies.

Only encrypted screenshots and encrypted authentication state may be uploaded.
The user performs QR confirmation and any required verification in Douyin.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from playwright.async_api import async_playwright
from app.browser import open_private_messages
from app.cloud_auth import save_cloud_state, write_encrypted
from scripts.login import _open_login


def directory() -> Path:
    return Path(os.environ["CLOUD_LOGIN_DIR"])


def status(phase: str, error: str = "") -> None:
    path = directory() / "status.json"
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps({"phase": phase, "error": error}), encoding="utf-8")
    temporary.replace(path)
    print(f"Cloud login: {phase}" + (f" ({error})" if error else ""), flush=True)


async def worker() -> None:
    directory().mkdir(parents=True, exist_ok=True)
    status("preparing")
    try:
        async with async_playwright() as playwright:
            browser = await playwright.chromium.launch(headless=True)
            context = await browser.new_context(
                viewport={"width": 1440, "height": 1000}, locale="zh-CN",
                timezone_id="Asia/Shanghai")
            page = await context.new_page()
            await page.goto("https://www.douyin.com/", wait_until="domcontentloaded", timeout=60000)
            await page.wait_for_timeout(4000)
            await _open_login(page)
            await page.wait_for_timeout(3000)
            deadline = time.monotonic() + 420
            next_capture = 0.0
            while time.monotonic() < deadline:
                # These cookies only come from this newly created browser.
                cookies = await context.cookies("https://www.douyin.com/")
                if any(c["name"] in {"sessionid", "sessionid_ss"} and c["value"] for c in cookies):
                    # Cookie presence alone is not proof of a usable login.
                    await open_private_messages(page)
                    await save_cloud_state(context, directory() / "state.enc")
                    status("success")
                    await browser.close()
                    return
                if time.monotonic() >= next_capture:
                    # Refresh only an explicitly expired QR, never solve or bypass a challenge.
                    refresh = page.get_by_text("刷新二维码", exact=True)
                    if await refresh.count() and await refresh.first.is_visible():
                        await refresh.first.click(timeout=3000)
                        await page.wait_for_timeout(1000)
                    screenshot = await page.screenshot(type="png", timeout=15000)
                    write_encrypted(directory() / "screen.enc", screenshot, "login-screen")
                    status("waiting")
                    next_capture = time.monotonic() + 10
                await asyncio.sleep(2)
            status("failed", "Login window expired; no state saved")
            await browser.close()
    except Exception as exc:
        # Playwright error text may contain page content or URLs with tokens.
        status("failed", type(exc).__name__)


def wait(seconds: int, ready: bool = False) -> None:
    deadline = time.monotonic() + seconds
    phase = "preparing"
    while time.monotonic() < deadline:
        path = directory() / "status.json"
        if path.exists():
            result = json.loads(path.read_text(encoding="utf-8"))
            phase = result["phase"]
            if phase == "failed":
                raise SystemExit("Cloud login stopped: " + result["error"])
            if phase == "success" or (ready and phase == "waiting"):
                break
        time.sleep(2)
    if ready and phase == "preparing":
        raise SystemExit("Cloud login page did not become ready")
    with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as output:
        output.write(f"phase={phase}\n")
    print(f"Cloud login: {phase}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=["worker", "wait"])
    parser.add_argument("--seconds", type=int, default=45)
    parser.add_argument("--ready", action="store_true")
    args = parser.parse_args()
    if args.mode == "worker":
        asyncio.run(worker())
    else:
        wait(args.seconds, args.ready)
