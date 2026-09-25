import { useState, type FormEvent } from 'react';
import { ApiError, login, type Me } from '../api';

export default function Login({ onSignedIn }: { onSignedIn: (me: Me) => void }) {
  const [token, setToken] = useState('');
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);

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
      if (err instanceof ApiError && err.status === 429) setError('Too many attempts. Wait a minute and try again.');
      else if (err instanceof ApiError && err.status === 401) setError('That token was not accepted.');
      else setError('Could not reach blastgate. Try again.');
    } finally {
      setBusy(false);
    }
  }

  return (
    <main className="login">
      <form className="login-card" onSubmit={submit}>
        <div className="login-brand">
          <span className="brand-mark" aria-hidden="true" />
          blastgate
        </div>
        <h1>Sign in</h1>
        <p className="lede">
          Use the login token from <code>blastgate approver new</code>.
        </p>
        <label className="field">
          <span>Login token</span>
          <input
            type="password"
            name="token"
            value={token}
            onChange={(e) => setToken(e.target.value)}
            autoComplete="off"
            spellCheck={false}
            autoFocus
            placeholder="bga_…"
          />
        </label>
        {error && (
          <p className="form-error" role="alert">
            {error}
          </p>
        )}
        <button type="submit" className="btn btn-primary btn-block" disabled={busy}>
          {busy ? 'Signing in…' : 'Sign in'}
        </button>
      </form>
    </main>
  );
}
