import "./LoginPage.css";

export const AuthLoadingScreen = () => {
  return (
    <div className="auth-splash-screen" role="status" aria-live="polite">
      <div className="auth-splash-logo">🛡️</div>
      <div className="login-spinner" style={{ width: "24px", height: "24px" }} />
      <div className="auth-splash-text">Verifying secure session...</div>
    </div>
  );
};
