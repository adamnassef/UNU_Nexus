import { useState, type FormEvent } from 'react';
import { Navigate, useLocation } from 'react-router-dom';
import BrandMark from '../components/BrandMark';
import { ALLOWED_EMAIL_DOMAIN, useAuth } from '../lib/auth';

export default function LoginPage() {
  const { user, sendMagicLink, supabaseReady } = useAuth();
  const location = useLocation();
  const [email, setEmail] = useState('');
  const [busy, setBusy] = useState(false);
  const [sent, setSent] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const from = (location.state as { from?: string } | null)?.from ?? '/';

  if (user) {
    return <Navigate to={from} replace />;
  }

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    setSent(false);
    try {
      await sendMagicLink(email);
      setSent(true);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not send sign-in link.');
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="login-page">
      <div className="login-brand">
        <div className="un-stripe" />
        <div className="login-brand-inner">
          <div className="login-brand-mark">
            <BrandMark
              emblemSize={88}
              variant="light"
              org="UNU Global Health"
              nameClassName="login-brand-name"
            />
          </div>

          <h1 className="login-headline">
            Institutional knowledge,<br />
            grounded in your sources.
          </h1>
          <p className="login-lead">
            Search reports and project material across UNU Global Health so you can find what you
            need quickly.
          </p>

          <ul className="login-points">
            <li>Cited answers from internal documents</li>
            <li>Upload and search your knowledge library</li>
            <li>For @{ALLOWED_EMAIL_DOMAIN} accounts only</li>
          </ul>
        </div>

        <div className="login-brand-foot">
          United Nations University · Global Health
        </div>
      </div>

      <div className="login-panel">
        <div className="login-card">
          <div className="login-card-header">
            <div className="login-card-eyebrow">Staff access</div>
            <h2 className="login-card-title">Sign in to continue</h2>
            <p className="login-card-sub">
              {supabaseReady
                ? `Enter your @${ALLOWED_EMAIL_DOMAIN} email. We’ll send a one-time magic link — no password.`
                : 'Add Supabase keys to .env.local (VITE_SUPABASE_URL and VITE_SUPABASE_ANON_KEY) to enable sign-in.'}
            </p>
          </div>

          {error && (
            <div className="login-error" role="alert">
              {error}
            </div>
          )}

          {sent ? (
            <div className="login-sent" role="status">
              <p className="login-sent-title">Check your email</p>
              <p className="login-sent-body">
                We sent a sign-in link to <strong>{email.trim().toLowerCase()}</strong>. Open it on
                this device to continue.
              </p>
              <button
                type="button"
                className="login-link-btn"
                onClick={() => {
                  setSent(false);
                  setError(null);
                }}
              >
                Use a different email
              </button>
            </div>
          ) : (
            <form onSubmit={handleSubmit} className="login-form">
              <label className="login-label" htmlFor="login-email">
                Work email
              </label>
              <input
                id="login-email"
                type="email"
                autoComplete="email"
                required
                disabled={busy || !supabaseReady}
                placeholder={`you@${ALLOWED_EMAIL_DOMAIN}`}
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                className="login-input"
              />
              <button
                type="submit"
                disabled={busy || !supabaseReady || !email.trim()}
                className="login-ms-btn"
              >
                {busy ? (
                  <span className="login-ms-spinner" aria-hidden="true" />
                ) : null}
                <span>{busy ? 'Sending link…' : 'Send magic link'}</span>
              </button>
            </form>
          )}

          <p className="login-card-note">
            Only @{ALLOWED_EMAIL_DOMAIN} addresses can request a link. Non-UNU emails are rejected.
          </p>
        </div>

        <p className="login-panel-foot">
          Need access? Contact your programme administrator.
        </p>
      </div>
    </div>
  );
}
