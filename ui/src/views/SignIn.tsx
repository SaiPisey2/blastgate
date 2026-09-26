import { useId, useState, type FormEvent } from 'react';
import { ApiError, login, type Me } from '../api';
import Button from '../components/Button';

// SignIn is the one screen before a session exists: a heading, one line
// of help, one token field and a button (spec §4.6).
export default function SignIn({ onSignedIn }: { onSignedIn: (me: Me) => void }) {
  const [token, setToken] = useState('');
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const fieldId = useId();
  const errorId = useId();

  async function submit(e: FormEvent) {
    e.preventDefault();
    const value = token.trim();
    // Cleared before the request, success or not: the token is a long-lived
    // credential and should sit in the page no longer than it takes to send.
    // It is never written to localStorage, sessionStorage or a cookie; the
    // server answers with its own HttpOnly session cookie instead.
    setToken('');
    if (!value) return;
    setBusy(true);
    setError('');
    try {
      onSignedIn(await login(value));
    } catch (err) {
      // One fixed line per kind of failure, never the server's own words:
      // a login error must not say whether a token exists, expired or was
      // revoked.
      if (err instanceof ApiError && err.status === 429) setError('Too many attempts. Wait a minute and try again.');
      else if (err instanceof ApiError && err.status === 401) setError('That token was not accepted.');
      else setError('Could not reach blastgate. Try again.');
    } finally {
      setBusy(false);
    }
  }

  return (
    <main className="sign-in">
      <form className="sign-in-box" onSubmit={submit}>
        <h1 className="sign-in-title">Sign in to blastgate</h1>
        <p className="sign-in-lede">Paste the token you were given.</p>
        <label className="sign-in-label" htmlFor={fieldId}>
          Login token
        </label>
        <input
          id={fieldId}
          className="sign-in-input mono"
          type="password"
          name="token"
          value={token}
          onChange={(e) => setToken(e.target.value)}
          // one-time-code: password managers neither offer to save it nor
          // autofill it, as they would for a plain password field.
          autoComplete="one-time-code"
          spellCheck={false}
          autoFocus
          placeholder="bga_…"
          aria-invalid={error ? true : undefined}
          aria-describedby={error ? errorId : undefined}
        />
        {error && (
          <p id={errorId} className="sign-in-error" role="alert">
            {error}
          </p>
        )}
        <Button type="submit" className="sign-in-submit" disabled={busy}>
          {busy ? 'Signing in…' : 'Sign in'}
        </Button>
      </form>
    </main>
  );
}
