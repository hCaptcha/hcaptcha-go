import HCaptcha from "@hcaptcha/react-hcaptcha";
import { useRef, useState } from "react";
import type { FormEvent } from "react";

const siteKey = import.meta.env.VITE_HCAPTCHA_SITEKEY;

export function App() {
  const captcha = useRef<HCaptcha>(null);
  const [token, setToken] = useState("");
  const [pending, setPending] = useState(false);
  const [result, setResult] = useState<unknown>(null);
  const [widgetError, setWidgetError] = useState("");

  async function submit(event: FormEvent) {
    event.preventDefault();
    setPending(true);
    setResult(null);

    try {
      const response = await fetch("/api/protected", {
        method: "POST",
        body: new URLSearchParams({ "h-captcha-response": token }),
      });
      const body = await response.json();
      setResult({ httpStatus: response.status, ...body });
    } catch (error) {
      setResult({ error: error instanceof Error ? error.message : String(error) });
    } finally {
      setPending(false);
      setToken("");
      captcha.current?.resetCaptcha();
    }
  }

  return (
    <main>
      <p className="eyebrow">PACKAGE E2E EXAMPLE</p>
      <h1>hCaptcha Go integration</h1>
      <p>
        Complete the challenge, then send the token through the Vite proxy to
        the Go backend. The response below includes the full Siteverify result.
      </p>
      {!siteKey && <p className="error">VITE_HCAPTCHA_SITEKEY is missing.</p>}
      {widgetError && <p className="error">{widgetError}</p>}
      {siteKey && (
        <form onSubmit={submit}>
          <HCaptcha
            ref={captcha}
            sitekey={siteKey}
            onVerify={(value) => {
              setWidgetError("");
              setToken(value);
            }}
            onExpire={() => setToken("")}
            onError={(error) => {
              setToken("");
              setWidgetError(String(error));
            }}
          />
          <button type="submit" disabled={!token || pending}>
            {pending ? "Verifying…" : "Verify token"}
          </button>
        </form>
      )}
      {result !== null && <pre>{JSON.stringify(result, null, 2)}</pre>}
    </main>
  );
}
