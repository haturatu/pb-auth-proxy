'use strict';

(() => {
    let browserInfo;
    let infoTime = 0;
    let controller;
    let requestID = 0;
    let renewal;
    const status = document.getElementById('passkey-status');
    const login = document.getElementById('passkey-login');
    const manager = document.getElementById('passkey-manager');
    const supported = window.isSecureContext && window.PublicKeyCredential && navigator.credentials;

    function message(text, error = false) {
        if (!status) return;
        status.textContent = text;
        status.className = error ? 'message error' : 'message';
    }
    async function info() {
        if (!browserInfo || Date.now() - infoTime > 10 * 60 * 1000) {
            const response = await fetch('/api/auth/browser', {credentials: 'same-origin'});
            if (!response.ok) throw new Error('Could not initialize authentication. Reload and try again.');
            browserInfo = await response.json();
            infoTime = Date.now();
        }
        return browserInfo;
    }
    async function api(path, method = 'GET', body) {
        const settings = await info();
        const response = await fetch(path, {
            method, credentials: 'same-origin',
            headers: {'Content-Type': 'application/json', 'X-XSRF-Token': settings.csrf_token},
            body: body === undefined ? undefined : JSON.stringify(body)
        });
        if (!response.ok) {
            const text = await response.text();
            throw new Error(text.trim() || 'The request failed. Try again.');
        }
        return response.json();
    }
    function decode(value) {
        const raw = atob(value.replace(/-/g, '+').replace(/_/g, '/'));
        return Uint8Array.from(raw, c => c.charCodeAt(0));
    }
    function encode(value) {
        return btoa(String.fromCharCode(...new Uint8Array(value))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    }
    function options(value, registration = false) {
        const result = value.publicKey;
        result.challenge = decode(result.challenge);
        if (registration) result.user.id = decode(result.user.id);
        for (const key of ['allowCredentials', 'excludeCredentials']) {
            if (result[key]) result[key] = result[key].map(item => ({...item, id: decode(item.id)}));
        }
        return result;
    }
    function serialize(credential) {
        const response = {};
        for (const key of ['clientDataJSON', 'attestationObject', 'authenticatorData', 'signature', 'userHandle']) {
            if (credential.response[key] != null) response[key] = encode(credential.response[key]);
        }
        if (credential.response.getTransports) response.transports = credential.response.getTransports();
        return {
            id: credential.id, rawId: encode(credential.rawId), type: credential.type,
            authenticatorAttachment: credential.authenticatorAttachment,
            clientExtensionResults: credential.getClientExtensionResults(), response
        };
    }
    function cancelLogin() {
        requestID++;
        controller?.abort();
        clearTimeout(renewal);
    }
    function friendlyError(error) {
        if (error.name === 'NotAllowedError') return 'Passkey request cancelled or timed out. Try again or use your password.';
        if (error.name === 'InvalidStateError') return 'This passkey is already registered. Choose another authenticator.';
        return error.message || 'Passkey authentication failed. Try again or use your password.';
    }
    async function signIn(conditional = false) {
        cancelLogin();
        const currentID = requestID;
        controller = new AbortController();
        const signal = controller.signal;
        if (!conditional) { login.disabled = true; login.setAttribute('aria-busy', 'true'); message('Waiting for your passkey…'); }
        try {
            const begin = await api('/api/auth/passkeys/login/begin', 'POST', {});
            if (currentID !== requestID) return;
            if (conditional) renewal = setTimeout(() => signIn(true), 4 * 60 * 1000);
            const credential = await navigator.credentials.get({publicKey: options(begin.options), mediation: conditional ? 'conditional' : 'optional', signal});
            if (currentID !== requestID || !credential) return;
            clearTimeout(renewal);
            const result = await api('/api/auth/passkeys/login/finish', 'POST', {ceremony_id: begin.ceremony_id, credential: serialize(credential)});
            window.location.assign(result.redirect);
        } catch (error) {
            if (currentID === requestID && error.name !== 'AbortError' && !conditional) message(friendlyError(error), true);
        } finally {
            if (!conditional) { login.disabled = false; login.removeAttribute('aria-busy'); }
        }
    }
    async function busy(button, work) {
        button.disabled = true;
        button.setAttribute('aria-busy', 'true');
        try { await work(); } catch (error) { message(friendlyError(error), true); }
        finally { button.disabled = false; button.removeAttribute('aria-busy'); }
    }
    async function listPasskeys() {
        const items = await api('/api/auth/passkeys');
        const list = document.getElementById('passkey-list');
        list.replaceChildren();
        if (!items.length) {
            const item = document.createElement('li');
            item.textContent = 'No passkeys yet. Add one below to sign in with your fingerprint, face or PIN.';
            list.append(item);
        }
        for (const item of items) {
            const row = document.createElement('li');
            const name = document.createElement('strong');
            name.textContent = item.name;
            const date = document.createElement('p');
            date.className = 'passkey-details';
            date.textContent = `Added ${new Date(item.created_at).toLocaleDateString()} · Last used ${item.last_used_at ? new Date(item.last_used_at).toLocaleDateString() : 'Never'}`;
            const remove = document.createElement('button');
            remove.type = 'button';
            remove.className = 'secondary-button';
            remove.textContent = `Delete ${item.name}`;
            remove.addEventListener('click', () => {
                if (!window.confirm(`Delete “${item.name}”? All sessions and API tokens will be revoked. You can still sign in with your password.`)) return;
                busy(remove, async () => {
                    const result = await api(`/api/auth/passkeys/${encodeURIComponent(item.id)}`, 'DELETE');
                    window.location.assign(result.redirect);
                });
            });
            row.append(name, date, remove);
            list.append(row);
        }
    }
    document.getElementById('login-form')?.addEventListener('submit', cancelLogin);
    window.addEventListener('pagehide', cancelLogin);

    async function init() {
        if (!login && !manager) return;
        try {
            const settings = await info();
            if (!settings.passkeys_enabled) return;
            if (login) {
                document.getElementById('passkey-signin').hidden = false;
                if (!supported) { login.disabled = true; message('Passkeys require a supported browser and a secure connection. Use your password to sign in.'); return; }
                login.addEventListener('click', () => signIn());
                if (await PublicKeyCredential.isConditionalMediationAvailable?.()) signIn(true);
            }
            if (manager) {
                manager.hidden = false;
                await listPasskeys();
                const add = document.getElementById('passkey-add-form');
                if (!supported) {
                    add.querySelector('button').disabled = true;
                    message('Adding passkeys requires a supported browser and a secure connection.');
                }
                document.getElementById('passkey-reauth-form').addEventListener('submit', event => {
                    event.preventDefault();
                    const form = event.currentTarget;
                    busy(form.querySelector('button'), async () => {
                        message('Verifying…');
                        await api('/api/auth/reauthenticate', 'POST', {password: new FormData(form).get('password')});
                        form.reset();
                        message('Identity verified. You can manage your passkeys for five minutes.');
                    });
                });
                add.addEventListener('submit', event => {
                    event.preventDefault();
                    busy(add.querySelector('button'), async () => {
                        message('Waiting for your authenticator…');
                        const begin = await api('/api/auth/passkeys/register/begin', 'POST', {name: new FormData(add).get('name')});
                        const credential = await navigator.credentials.create({publicKey: options(begin.options, true)});
                        if (!credential) throw new Error('No passkey was created. Try again.');
                        await api('/api/auth/passkeys/register/finish', 'POST', {ceremony_id: begin.ceremony_id, credential: serialize(credential)});
                        add.reset();
                        await listPasskeys();
                        document.getElementById('passkey-name').focus();
                        message('Passkey added. Keep your password as a recovery method.');
                    });
                });
            }
        } catch (error) { message(friendlyError(error), true); }
    }
    init();
})();
