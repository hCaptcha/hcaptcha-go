# End-to-end example

This application exercises the checked-out Go package through a React/Vite UI
with [hCaptcha's React component](https://docs.hcaptcha.com/integrations/react).
Vite proxies `/api/protected` to the loopback-only Go backend, so browser requests
remain same-origin.

## Run

```sh
cd example
cp .env.local.example .env.local
npm install
./run.sh
```

hCaptcha's [local development guide](https://docs.hcaptcha.com/#local-development)
lists `localhost` and `127.0.0.1` as unsupported hostnames. On a loopback URL,
this example can still show a challenge and pass Siteverify, though users may
need to click the checkbox a few times. The hostname warning makes that flow
unreliable. To solve challenges locally without the warning:

1. Choose a development hostname under a domain you control, such as
   `captcha-dev.example.com` (replace this placeholder with your own hostname).
2. Map it to loopback in your hosts file (`/private/etc/hosts` on macOS,
   `/etc/hosts` on Linux, or `C:\Windows\System32\Drivers\etc\hosts` on Windows):

   ```text
   127.0.0.1 captcha-dev.example.com
   ```

3. Add `ALLOWED_HOSTS=captcha-dev.example.com` to `.env.local`. If
   [domain allowlisting](https://docs.hcaptcha.com/configuration#domain-allowlist)
   is enabled for your hCaptcha sitekey, add the same hostname there.
4. Run `./run.sh` and open `http://captcha-dev.example.com:3000`.

The [public test credentials](https://docs.hcaptcha.com/#integration-testing-test-keys)
in `.env.local.example` validate integration wiring. They never show a visual
challenge and provide no anti-bot protection. Use your own sitekey and matching
secret to exercise a real challenge. For a reverse proxy, add its public hostname
to `ALLOWED_HOSTS` and, when enabled, the sitekey's domain allowlist. If hCaptcha
reports [`network-error`](https://docs.hcaptcha.com/configuration#error-codes)
on the mapped hostname, inspect browser requests and blockers.

The backend binds to `127.0.0.1:8080`. It accepts `X-Forwarded-For` only from a
loopback peer (the Vite proxy), sends that IP and the expected sitekey to
[Siteverify](https://docs.hcaptcha.com/#verify-the-user-response-server-side),
and returns the full Siteverify result for inspection. Do not copy
that diagnostic response behavior into a production endpoint.

## Expected checks

- Completing a challenge returns HTTP 200 and `siteverify.success: true`.
- An invalid token returns HTTP 403. With real keys, reusing a token also
  returns HTTP 403; the public test token always verifies successfully with
  its matching test secret.
- Submitting without a token is disabled in the UI; a direct empty request
  returns HTTP 400.
- Stopping the Go backend causes the proxy request to fail, proving verification
  is server-side and fail-closed.
