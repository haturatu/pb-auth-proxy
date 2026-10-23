"""Real browser + PocketBase passkey tests for both supported frontends.

Requirements: PB_BINARY, Chromium, PHP-FPM, and pip install playwright.
Run: PB_BINARY=/path/to/pocketbase python3 tests/passkeys_e2e.py
All services use fresh temporary data and random localhost ports.
"""
import base64
import contextlib
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import tempfile
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor

from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parents[1]
PASSWORD = "Recovery-password-123!"


def port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def wait(url, process):
    for _ in range(200):
        if process.poll() is not None:
            raise RuntimeError(f"Service exited: {process.args}")
        try:
            urllib.request.urlopen(url, timeout=0.2).close()
            return
        except OSError:
            time.sleep(0.05)
    raise RuntimeError(f"Service did not start: {url}")


@contextlib.contextmanager
def service(args, log, **kwargs):
    process = subprocess.Popen(args, stdout=log, stderr=log, **kwargs)
    try:
        yield process
    finally:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()


def post(context, url, data, headers=None):
    return context.request.post(url, data=data, headers=headers or {})


def exercise(browser, origin, mode, pb):
    context = browser.new_context(viewport={"width": 390, "height": 844})
    page = context.new_page()
    errors = []
    page.on("pageerror", lambda error: errors.append(str(error)))
    cdp = context.new_cdp_session(page)
    cdp.send("WebAuthn.enable")
    authenticator = cdp.send("WebAuthn.addVirtualAuthenticator", {"options": {
        "protocol": "ctap2", "transport": "internal", "hasResidentKey": True,
        "hasUserVerification": True, "isUserVerified": True,
        "automaticPresenceSimulation": True,
    }})["authenticatorId"]
    username = f"browser-{mode}"
    page.goto(origin + "/register")
    page.locator('[name="username"]').fill(username)
    page.locator('[name="password"]').fill(PASSWORD)
    page.locator('[name="confirm_password"]').fill(PASSWORD)
    page.get_by_role("button", name="Register", exact=True).click()
    page.wait_for_url(origin + "/login")
    page.locator('[name="username"]').fill(username)
    page.locator('[name="password"]').fill(PASSWORD)
    page.get_by_role("button", name="Login", exact=True).click()
    page.wait_for_url(origin + "/")
    page.goto(origin + "/account")
    page.locator('#passkey-manager').wait_for(state="visible")
    page.locator('#passkey-name').fill("Personal phone")
    page.get_by_role("button", name="Add a passkey", exact=True).click()
    page.get_by_text("Passkey added. Keep your password as a recovery method.", exact=True).wait_for()
    assert page.get_by_text("Personal phone", exact=True).count() == 1
    first_cookie = next(c["value"] for c in context.cookies() if c["name"] == "auth_token")
    credentials = cdp.send("WebAuthn.getCredentials", {"authenticatorId": authenticator})["credentials"]
    assert len(credentials) == 1
    assert credentials[0]["isResidentCredential"]
    assert page.evaluate('document.documentElement.scrollWidth <= window.innerWidth'), 'Mobile overflow'
    artifacts = Path(os.environ.get('E2E_ARTIFACTS_DIR', str(pb)))
    artifacts.mkdir(parents=True, exist_ok=True)
    page.screenshot(path=str(artifacts / f"{mode}-account.png"), full_page=True)

    # The exclusion list deliberately rejects registering the same authenticator
    # twice. Use a different virtual device for the second passkey.
    cdp.send("WebAuthn.removeVirtualAuthenticator", {"authenticatorId": authenticator})
    authenticator = cdp.send("WebAuthn.addVirtualAuthenticator", {"options": {
        "protocol": "ctap2", "transport": "internal", "hasResidentKey": True,
        "hasUserVerification": True, "isUserVerified": True,
        "automaticPresenceSimulation": True,
    }})["authenticatorId"]
    # Register a second discoverable credential and keep both independent entries.
    page.locator('#passkey-name').fill("Backup key")
    page.get_by_role("button", name="Add a passkey", exact=True).click()
    page.get_by_text("Backup key", exact=True).wait_for()
    assert page.locator('#passkey-list li').count() == 2

    info = context.request.get(origin + "/api/auth/browser").json()
    headers = {"Origin": origin, "X-XSRF-Token": info["csrf_token"]}
    # Origin, CSRF, and unsupported methods must fail before WebAuthn work.
    assert post(context, origin + "/api/auth/passkeys/login/begin", {}).status == 403
    assert post(context, origin + "/api/auth/passkeys/login/begin", {}, {**headers, "Origin": "https://evil.example"}).status == 403
    assert context.request.get(origin + "/api/auth/passkeys/login/begin").status == 405
    assert post(context, origin + "/api/auth/passkeys/register/begin", {"name": ""}, headers).status == 400

    # Password API tokens rotate once; parallel refresh requests have one winner.
    tokens = post(context, origin + "/api/auth/token", {"username": username, "password": PASSWORD}).json()
    assert context.request.get(origin + "/api/health", headers={"Authorization": "Bearer " + tokens["access_token"]}).status == 200
    def refresh(_):
        import urllib.error
        req = urllib.request.Request(origin + "/api/auth/refresh", data=json.dumps({"refresh_token": tokens["refresh_token"]}).encode(), headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req) as response:
                return response.status
        except urllib.error.HTTPError as error:
            return error.code
    with ThreadPoolExecutor(max_workers=5) as pool:
        statuses = list(pool.map(refresh, range(5)))
    assert statuses.count(200) == 1, statuses
    assert statuses.count(401) == 4, statuses

    page.goto(origin + "/logout")
    page.get_by_role("button", name="Sign out", exact=True).click()
    page.wait_for_url(origin + "/login")
    # A copied pre-logout cookie cannot authenticate anymore.
    revoked = browser.new_context()
    revoked.add_cookies([{"name": "auth_token", "value": first_cookie, "url": origin}])
    assert revoked.request.get(origin + "/account", max_redirects=0).status == 302
    revoked.close()

    # Chromium's virtual authenticator automatically completes Conditional UI.
    page.wait_for_url(origin + "/")
    context.add_init_script("Object.defineProperty(PublicKeyCredential, 'isConditionalMediationAvailable', {value: async () => false})")
    page.goto(origin + "/logout")
    page.get_by_role("button", name="Sign out", exact=True).click()
    page.wait_for_url(origin + "/login")
    # The explicit path also works on browsers without conditional mediation.
    page.get_by_role("button", name="Sign in with a passkey", exact=True).click()
    page.wait_for_url(origin + "/")
    page.goto(origin + "/account")
    page.get_by_text("Personal phone", exact=True).wait_for()
    used = context.request.get(origin + "/api/auth/passkeys").json()
    assert any(item["last_used_at"] for item in used)

    # Use actual signed assertions, then corrupt individual verification inputs.
    def assertion():
        return page.evaluate(r"""async () => {
            const info = await (await fetch('/api/auth/browser')).json();
            const begin = await (await fetch('/api/auth/passkeys/login/begin', {
                method: 'POST', headers: {'Content-Type': 'application/json', 'X-XSRF-Token': info.csrf_token}, body: '{}'
            })).json();
            const decode = value => Uint8Array.from(atob(value.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0));
            const encode = value => btoa(String.fromCharCode(...new Uint8Array(value))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
            const options = begin.options.publicKey;
            options.challenge = decode(options.challenge);
            const credential = await navigator.credentials.get({publicKey: options});
            const response = {};
            for (const key of ['clientDataJSON', 'authenticatorData', 'signature', 'userHandle']) response[key] = encode(credential.response[key]);
            return {ceremony_id: begin.ceremony_id, credential: {id: credential.id, rawId: encode(credential.rawId), type: credential.type, response, clientExtensionResults: credential.getClientExtensionResults()}};
        }""")

    def decode(value):
        return base64.urlsafe_b64decode(value + '=' * (-len(value) % 4))

    def encode(value):
        return base64.urlsafe_b64encode(value).decode().rstrip('=')

    for corrupt in ['challenge', 'origin', 'rp_id', 'uv', 'signature', 'user_handle']:
        body = assertion()
        response = body['credential']['response']
        if corrupt in ['challenge', 'origin']:
            client = json.loads(decode(response['clientDataJSON']))
            client[corrupt] = 'https://evil.example' if corrupt == 'origin' else 'wrong-challenge'
            response['clientDataJSON'] = encode(json.dumps(client).encode())
        elif corrupt in ['rp_id', 'uv']:
            auth = bytearray(decode(response['authenticatorData']))
            if corrupt == 'rp_id':
                auth[0] ^= 1
            else:
                auth[32] &= ~4
            response['authenticatorData'] = encode(auth)
        elif corrupt == 'signature':
            signature = bytearray(decode(response['signature']))
            signature[-1] ^= 1
            response['signature'] = encode(signature)
        else:
            response['userHandle'] = encode(b'another-user-id')
        info = context.request.get(origin + '/api/auth/browser').json()
        headers = {'Origin': origin, 'X-XSRF-Token': info['csrf_token']}
        assert post(context, origin + '/api/auth/passkeys/login/finish', body, headers).status == 401, corrupt
        assert post(context, origin + '/api/auth/passkeys/login/finish', body, headers).status == 400, 'replay: ' + corrupt

    body = assertion()
    another_browser = browser.new_context()
    other_info = another_browser.request.get(origin + '/api/auth/browser').json()
    assert post(another_browser, origin + '/api/auth/passkeys/login/finish', body, {'Origin': origin, 'X-XSRF-Token': other_info['csrf_token']}).status == 400
    another_browser.close()
    assert post(context, origin + '/api/auth/passkeys/login/finish', body, headers).status == 200

    # Deletion requires a recent login, is confirmed, and revokes every token.
    page.on("dialog", lambda dialog: dialog.accept())
    page.get_by_role("button", name="Delete Personal phone", exact=True).click()
    page.wait_for_url(origin + "/login")
    assert context.request.get(origin + "/account", max_redirects=0).status == 302
    assert context.request.get(origin + "/api/health", headers={"Authorization": "Bearer " + tokens["access_token"]}).status == 401
    # Existing password remains a recovery path after a passkey is removed.
    page.locator('[name="username"]').fill(username)
    page.locator('[name="password"]').fill(PASSWORD)
    page.get_by_role("button", name="Login", exact=True).click()
    page.wait_for_url(origin + "/")
    page.goto(origin + "/account")
    page.get_by_text("Backup key", exact=True).wait_for()
    page.locator('#passkey-password').fill(PASSWORD)
    page.get_by_role("button", name="Verify identity", exact=True).click()
    page.get_by_text("Identity verified. You can manage your passkeys for five minutes.", exact=True).wait_for()
    assert not errors, errors
    context.close()
    print(f"PASS: {mode}: register two passkeys, conditional/explicit login, invalid assertions, CSRF, refresh race, revocation, password recovery")


def main():
    binary = os.environ.get("PB_BINARY")
    if not binary:
        raise SystemExit("Set PB_BINARY to PocketBase 0.36.9")
    with tempfile.TemporaryDirectory(prefix="pb-passkey-e2e-") as temporary:
        work = Path(temporary)
        executable = work / "server"
        subprocess.run(["go", "build", "-o", str(executable), "./cmd/server"], cwd=ROOT, check=True)
        pb_port = port()
        pb_url = f"http://127.0.0.1:{pb_port}"
        fpm_socket = work / "php.sock"
        fpm_config = work / "php-fpm.conf"
        fpm_config.write_text(f"[global]\ndaemonize = no\nerror_log = {work / 'php.log'}\n[www]\nlisten = {fpm_socket}\npm = static\npm.max_children = 2\n")
        with (work / "services.log").open("w+") as log:
            try:
                with service([binary, "serve", f"--http=127.0.0.1:{pb_port}", f"--dir={work / 'data'}", f"--migrationsDir={ROOT / 'pb_migrations'}"], log) as pocketbase, service([os.environ.get("PHP_FPM_BINARY", "php-fpm"), "-y", str(fpm_config)], log):
                    wait(pb_url + "/api/health", pocketbase)
                    with sync_playwright() as playwright:
                        browser = playwright.chromium.launch(executable_path=os.environ.get("CHROMIUM_BINARY") or shutil.which("chromium"), headless=True, args=["--no-sandbox"])
                        for mode in ["js", "php"]:
                            app_port = port()
                            origin = f"http://localhost:{app_port}"
                            env = {**os.environ, "LISTEN_PORT": str(app_port), "TARGET_URL": pb_url,
                                   "POCKETBASE_URL": pb_url, "POCKETBASE_SUPERUSER_EMAIL": "admin@example.com", "POCKETBASE_SUPERUSER_PASSWORD": "change-me-now",
                                   "SESSION_SECRET": "e2e-browser-test-secret-at-least-32-bytes", "XSRF_SECRET_KEY": base64.b64encode(b"0123456789abcdef0123456789abcdef").decode(),
                                   "PUBLIC_ORIGIN": origin, "COOKIE_SECURE": "false", "WEBAUTHN_ENABLED": "true", "WEBAUTHN_RP_ID": "localhost", "WEBAUTHN_ORIGIN": origin,
                                   "PROTECT_FRONTEND": "true", "PROTECT_API": "true", "FRONTEND_TYPE": mode, "PHP_FPM_SOCKET": str(fpm_socket)}
                            with service([str(executable)], log, env=env, cwd=ROOT) as server:
                                wait(origin + "/login", server)
                                exercise(browser, origin, mode, work)
                        browser.close()
            except Exception:
                log.flush()
                print(Path(log.name).read_text()[-12000:])
                raise


if __name__ == "__main__":
    main()
