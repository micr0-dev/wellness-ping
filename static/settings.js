// Settings page behaviour. No inline handlers: every listener is attached here
// so the page works under a CSP without 'unsafe-inline'.

(function () {
    function csrfToken() {
        const el = document.getElementById('csrf');
        return el ? el.value : '';
    }

    function toggleModule(name) {
        const box = document.getElementById(name + '_enable');
        const body = document.getElementById(name + '-body');
        const module = document.getElementById(name + '-mod');
        if (!box || !body || !module) return;

        const enabled = box.checked;
        module.classList.toggle('greyed', !enabled);
        body.querySelectorAll('input, textarea').forEach(el => {
            if (el.type === 'hidden') return;
            if (enabled) { el.removeAttribute('disabled'); } else { el.setAttribute('disabled', 'disabled'); }
        });
    }

    async function registerPasskey() {
        const status = document.getElementById('passkey-status');
        status.textContent = 'Contacting server...';
        try {
            // Registration begins with a POST carrying the CSRF token: it
            // mints a server-side ceremony session, so it is a state change.
            const optsResp = await fetch('/passkey-register-begin', {
                method: 'POST',
                headers: { 'X-CSRF-Token': csrfToken() }
            });
            if (!optsResp.ok) { status.textContent = await optsResp.text(); return; }
            const options = await optsResp.json();
            options.publicKey.challenge = b64urlToBuf(options.publicKey.challenge);
            options.publicKey.user.id = b64urlToBuf(options.publicKey.user.id);

            const cred = await navigator.credentials.create(options);

            const payload = {
                id: cred.id,
                rawId: bufToB64url(cred.rawId),
                type: cred.type,
                response: {
                    clientDataJSON: bufToB64url(cred.response.clientDataJSON),
                    attestationObject: bufToB64url(cred.response.attestationObject),
                },
                extensions: cred.getClientExtensionResults()
            };

            const resp = await fetch('/passkey-register-finish', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrfToken() },
                body: JSON.stringify(payload)
            });
            if (resp.ok) {
                status.textContent = 'Passkey registered.';
                setTimeout(() => location.reload(), 800);
            } else {
                status.textContent = await resp.text();
            }
        } catch (e) {
            status.textContent = 'Passkey failed: ' + e.message;
        }
    }

    window.addEventListener('DOMContentLoaded', () => {
        ['pin', 'totp', 'passkey'].forEach(name => {
            const box = document.getElementById(name + '_enable');
            if (!box) return;
            box.addEventListener('change', () => toggleModule(name));
            toggleModule(name);
        });

        document.querySelectorAll('[data-nav]').forEach(btn => {
            btn.addEventListener('click', () => { location.href = btn.dataset.nav; });
        });

        document.querySelectorAll('[data-action="register-passkey"]').forEach(btn => {
            btn.addEventListener('click', registerPasskey);
        });
    });
})();
