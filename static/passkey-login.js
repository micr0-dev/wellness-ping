// Passkey step of a check-in or settings login.
// Configuration comes from data attributes rather than an inline script, so no
// server-rendered value is ever interpolated into executable JavaScript.

(function () {
    const btn = document.getElementById('passkey-btn');
    if (!btn) return;

    const token = btn.dataset.token || '';
    const action = btn.dataset.action || '/';

    async function startPasskey() {
        const status = document.getElementById('status');
        status.textContent = 'Contacting server...';
        try {
            const optsResp = await fetch('/passkey-login-begin?token=' + encodeURIComponent(token));
            if (!optsResp.ok) throw new Error(await optsResp.text());
            const options = await optsResp.json();
            options.publicKey.challenge = b64urlToBuf(options.publicKey.challenge);
            if (options.publicKey.allowCredentials) {
                options.publicKey.allowCredentials.forEach(c => { c.id = b64urlToBuf(c.id); });
            }

            const cred = await navigator.credentials.get(options);

            const payload = {
                id: cred.id,
                rawId: bufToB64url(cred.rawId),
                type: cred.type,
                response: {
                    clientDataJSON: bufToB64url(cred.response.clientDataJSON),
                    authenticatorData: bufToB64url(cred.response.authenticatorData),
                    signature: bufToB64url(cred.response.signature),
                },
                extensions: cred.getClientExtensionResults()
            };
            if (cred.response.userHandle) {
                payload.response.userHandle = bufToB64url(cred.response.userHandle);
            }

            const resp = await fetch('/passkey-login-finish?token=' + encodeURIComponent(token), {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            });
            if (resp.ok) {
                window.location.href = action;
            } else {
                status.textContent = await resp.text();
            }
        } catch (e) {
            status.textContent = 'Passkey failed: ' + e.message;
        }
    }

    btn.addEventListener('click', startPasskey);
})();
