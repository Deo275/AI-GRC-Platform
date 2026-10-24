/**
 * Centralized API Client for AI-GRC Platform.
 *
 * Enforces:
 * - Bearer JWT authorization on all authenticated requests
 * - Centralized HTTP 401 session expiration handling
 * - Centralized HTTP 403 permission error handling
 * - Single-source API base URL configuration
 * - Authoritative Bearer JWT authentication for server-side operator attribution
 */

export const API_BASE =
  import.meta.env.VITE_API_BASE_URL || "http://127.0.0.1:8000";

export const AUTH_TOKEN_KEY = "ai_grc_access_token";

export const DEV_ADMIN_USER = {
  id: 1,
  username: "admin",
  email: "admin@example.com",
  display_name: "Administrator (Dev)",
  role: "Administrator",
  is_active: true,
};

/**
 * Converts string, object, or array API error details into safe, readable strings.
 * Prevents React rendering crashes from non-string error payloads.
 */
export const formatApiError = (detail, fallback = "An unexpected error occurred") => {
  if (!detail) return fallback;
  if (typeof detail === "string") return detail;
  if (Array.isArray(detail)) {
    return detail
      .map((item) => (typeof item === "string" ? item : item?.msg || JSON.stringify(item)))
      .join("; ");
  }
  if (typeof detail === "object") {
    return detail.message || detail.error || JSON.stringify(detail);
  }
  return String(detail);
};

let onUnauthorizedCallback = null;
let onForbiddenCallback = null;

export const setUnauthorizedHandler = (fn) => {
  onUnauthorizedCallback = fn;
};

export const setForbiddenHandler = (fn) => {
  onForbiddenCallback = fn;
};

// Retained as no-op for backward compatibility with AuthContext
export const setCurrentUserGetter = () => {};

export const getStoredToken = () => {
  try {
    return sessionStorage.getItem(AUTH_TOKEN_KEY);
  } catch {
    return null;
  }
};

export const setStoredToken = (token) => {
  try {
    if (token) {
      sessionStorage.setItem(AUTH_TOKEN_KEY, token);
    } else {
      sessionStorage.removeItem(AUTH_TOKEN_KEY);
    }
  } catch (err) {
    console.error("Unable to access sessionStorage:", err);
  }
};

export const removeStoredToken = () => {
  try {
    sessionStorage.removeItem(AUTH_TOKEN_KEY);
  } catch (err) {
    console.error("Unable to clear sessionStorage:", err);
  }
};

/**
 * Core authenticated fetch wrapper.
 * Prepends API_BASE for relative URLs and attaches Bearer authorization.
 * Handles 401/403 status codes centrally.
 */
export const authFetch = async (url, options = {}) => {
  const fullUrl = url.startsWith("http://") || url.startsWith("https://")
    ? url
    : `${API_BASE}${url.startsWith("/") ? "" : "/"}${url}`;

  const headers = new Headers(options.headers || {});

  // Attach JWT Bearer token if available
  const token = getStoredToken();
  if (token && !headers.has("Authorization")) {
    headers.set("Authorization", `Bearer ${token}`);
  }

  let response;
  try {
    response = await fetch(fullUrl, {
      ...options,
      headers,
    });
  } catch (err) {
    console.error("Network or connectivity error:", err);
    const networkError = new Error("Unable to connect to the server. Please try again.");
    networkError.isNetworkError = true;
    throw networkError;
  }

  // Handle HTTP 401 Unauthorized centrally
  if (response.status === 401) {
    // Exclude public /auth/login so invalid credentials display on the login form
    const isLoginEndpoint = fullUrl.endsWith("/auth/login");
    if (!isLoginEndpoint) {
      removeStoredToken();
      if (onUnauthorizedCallback) {
        onUnauthorizedCallback("Your session has expired. Please sign in again.");
      }
    }
  }

  // Handle HTTP 403 Forbidden centrally (do NOT log user out)
  if (response.status === 403) {
    if (onForbiddenCallback) {
      onForbiddenCallback("You do not have permission to perform this action.");
    }
  }

  return response;
};

export const isDockerEnv = () => {
  return import.meta.env.VITE_IS_DOCKER === "true";
};

/**
 * Authentication API helpers
 */
export const apiDevLogin = async () => {
  let response;
  try {
    response = await fetch(`${API_BASE}/auth/dev-login`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
    });
  } catch (err) {
    const error = new Error("Unable to connect to backend for dev login: " + (err?.message || ""));
    error.isNetworkError = true;
    throw error;
  }

  if (!response.ok) {
    throw new Error(`Dev login request failed with status ${response.status}`);
  }

  return await response.json();
};

export const apiLogin = async (username, password) => {
  let response;
  try {
    response = await fetch(`${API_BASE}/auth/login`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        username: username.trim(),
        password,
      }),
    });
  } catch {
    throw new Error("Unable to connect to the server. Please try again.");
  }

  if (!response.ok) {
    if (response.status === 401) {
      throw new Error("Invalid username or password.");
    }
    throw new Error("Authentication request failed. Please try again.");
  }

  return await response.json();
};

export const apiGetMe = async (tokenOverride = null) => {
  const token = tokenOverride || getStoredToken();
  if (!token) {
    throw new Error("No authentication token available.");
  }

  let response;
  try {
    response = await fetch(`${API_BASE}/auth/me`, {
      method: "GET",
      headers: {
        Authorization: `Bearer ${token}`,
      },
    });
  } catch {
    throw new Error("Unable to connect to the server. Please try again.");
  }

  if (!response.ok) {
    if (response.status === 401) {
      removeStoredToken();
      const err = new Error("Your session has expired. Please sign in again.");
      err.status = 401;
      throw err;
    }
    throw new Error(`Failed to load user profile (Status ${response.status})`);
  }

  return await response.json();
};

export const apiLogout = async () => {
  const token = getStoredToken();
  if (token) {
    try {
      await fetch(`${API_BASE}/auth/logout`, {
        method: "POST",
        headers: {
          Authorization: `Bearer ${token}`,
          "Content-Type": "application/json",
        },
      });
    } catch (err) {
      console.warn("Backend logout notification warning:", err);
    }
  }
  removeStoredToken();
};
