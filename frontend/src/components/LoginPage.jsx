import { useState } from "react";
import { useAuth } from "../context/useAuth";
import "./LoginPage.css";

export const LoginPage = () => {
  const { login, authError, clearAuthError } = useAuth();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [localError, setLocalError] = useState(null);
  const [isSubmitting, setIsSubmitting] = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!username.trim() || !password) {
      setLocalError("Please enter both username/email and password.");
      return;
    }

    setLocalError(null);
    clearAuthError();
    setIsSubmitting(true);

    try {
      await login(username.trim(), password);
    } catch (err) {
      if (err?.isNetworkError || err?.message?.includes("Unable to connect")) {
        setLocalError("Unable to connect to the server. Please try again.");
      } else {
        setLocalError("Invalid username or password.");
      }
    } finally {
      setIsSubmitting(false);
    }
  };

  const displayError = localError || authError;

  return (
    <div className="login-page-container">
      <div className="login-card">
        <div className="login-brand-header">
          <div className="login-logo-badge">🛡️</div>
          <h1 className="login-title">AI-GRC Platform</h1>
          <p className="login-subtitle">
            Enterprise Governance, Risk Management & Automated Compliance
          </p>
        </div>

        {displayError && (
          <div className="login-alert login-alert-error" role="alert">
            <span>⚠️</span>
            <div>{displayError}</div>
          </div>
        )}

        <form className="login-form" onSubmit={handleSubmit} noValidate>
          <div className="login-field">
            <label className="login-label" htmlFor="username-input">
              Username or Email
            </label>
            <input
              id="username-input"
              className="login-input"
              type="text"
              autoComplete="username"
              value={username}
              onChange={(e) => {
                setUsername(e.target.value);
                if (localError) setLocalError(null);
              }}
              placeholder="operator@organization.local"
              disabled={isSubmitting}
              required
            />
          </div>

          <div className="login-field">
            <label className="login-label" htmlFor="password-input">
              Password
            </label>
            <input
              id="password-input"
              className="login-input"
              type="password"
              autoComplete="current-password"
              value={password}
              onChange={(e) => {
                setPassword(e.target.value);
                if (localError) setLocalError(null);
              }}
              placeholder="••••••••••••"
              disabled={isSubmitting}
              required
            />
          </div>

          <button
            id="login-submit-button"
            className="login-submit-btn"
            type="submit"
            disabled={isSubmitting}
          >
            {isSubmitting ? (
              <>
                <span className="login-spinner" />
                <span>Signing in...</span>
              </>
            ) : (
              <span>Sign In</span>
            )}
          </button>
        </form>

        <div className="login-footer-meta">
          <div className="login-security-tag">
            <span>🔒</span> Authoritative GRC System • Server-Side RBAC
          </div>
        </div>
      </div>
    </div>
  );
};
