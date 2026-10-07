/**
 * Centralized API Client for AI-GRC Platform.
 *
 * Enforces:
 * - Bearer JWT authorization on all authenticated requests
 * - Centralized HTTP 401 session expiration handling
 * - Centralized HTTP 403 permission error handling
 * - Single-source API base URL configuration
 * - Backward-compatible operator identity attribution from authenticated profile
 */

export const API_BASE =
  import.meta.env.VITE_API_BASE_URL || "http://127.0.0.1:8000";

export const AUTH_TOKEN_KEY = "ai_grc_access_token";

let onUnauthorizedCallback = null;
let onForbiddenCallback = null;
let currentUserGetter = null;

export const setUnauthorizedHandler = (fn) => {
  onUnauthorizedCallback = fn;
};

export const setForbiddenHandler = (fn) => {
  onForbiddenCallback = fn;
};

export const setCurrentUserGetter = (fn) => {
  currentUserGetter = fn;
};

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

  // Provide operator headers derived strictly from authenticated user profile for backward compatibility
  if (currentUserGetter) {
    const user = currentUserGetter();
    if (user) {
      if (!headers.has("X-Operator-Name")) {
        headers.set("X-Operator-Name", user.display_name || user.username || "Authenticated User");
      }
      if (!headers.has("X-Operator-Role")) {
        headers.set("X-Operator-Role", user.role || "Security Analyst");
      }
    }
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

/**
 * Authentication API helpers
 */
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
