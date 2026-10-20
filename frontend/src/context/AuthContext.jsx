import { useState, useEffect, useCallback, useMemo } from "react";
import { AuthContext } from "./authContextDef";
import {
  getStoredToken,
  setStoredToken,
  removeStoredToken,
  setUnauthorizedHandler,
  setForbiddenHandler,
  setCurrentUserGetter,
  apiLogin,
  apiDevLogin,
  apiGetMe,
  isDockerEnv,
  DEV_ADMIN_USER,
} from "../api/client";

export const AuthProvider = ({ children }) => {
  const [token, setToken] = useState(() => getStoredToken());
  const [user, setUser] = useState(null);
  const [isLoading, setIsLoading] = useState(true);
  const [authError, setAuthError] = useState(null);
  const [permissionNotice, setPermissionNotice] = useState(null);

  // Wire up centralized callbacks for API client
  useEffect(() => {
    setUnauthorizedHandler((message) => {
      if (!isDockerEnv()) {
        apiDevLogin()
          .then((devData) => {
            setStoredToken(devData.access_token);
            setToken(devData.access_token);
            setUser(devData.user);
          })
          .catch(() => {
            setToken("dev-bypass-token");
            setUser(DEV_ADMIN_USER);
          });
        return;
      }

      removeStoredToken();
      setToken(null);
      setUser(null);
      setAuthError(message || "Your session has expired. Please sign in again.");
    });

    setForbiddenHandler((message) => {
      setPermissionNotice(message || "You do not have permission to perform this action.");
    });
  }, []);

  // Provide current user getter to API client for operator attribution headers
  useEffect(() => {
    setCurrentUserGetter(() => user);
  }, [user]);

  // Initial startup token validation
  useEffect(() => {
    let isMounted = true;

    const verifySession = async () => {
      const isDocker = isDockerEnv();

      // Non-Docker mode: bypass login screen and automatically grant Administrator access
      if (!isDocker) {
        try {
          const devData = await apiDevLogin();
          if (isMounted) {
            setStoredToken(devData.access_token);
            setToken(devData.access_token);
            setUser(devData.user);
            setAuthError(null);
            setIsLoading(false);
          }
          return;
        } catch (err) {
          console.warn("Dev auto-login endpoint unavailable, falling back to local dev admin session:", err);
          if (isMounted) {
            const fallbackToken = getStoredToken() || "dev-bypass-token";
            setToken(fallbackToken);
            setUser(DEV_ADMIN_USER);
            setAuthError(null);
            setIsLoading(false);
          }
          return;
        }
      }

      // Docker mode: verify stored session
      const stored = getStoredToken();
      if (!stored) {
        if (isMounted) {
          setIsLoading(false);
          setUser(null);
          setToken(null);
        }
        return;
      }

      try {
        const userData = await apiGetMe(stored);
        if (isMounted) {
          setUser(userData);
          setToken(stored);
          setAuthError(null);
        }
      } catch (err) {
        if (isMounted) {
          removeStoredToken();
          setToken(null);
          setUser(null);
          if (err?.status === 401) {
            setAuthError("Your session has expired. Please sign in again.");
          }
        }
      } finally {
        if (isMounted) {
          setIsLoading(false);
        }
      }
    };

    verifySession();

    return () => {
      isMounted = false;
    };
  }, []);

  const login = useCallback(async (username, password) => {
    setAuthError(null);
    const data = await apiLogin(username, password);
    const accessToken = data.access_token;
    const userProfile = data.user;

    setStoredToken(accessToken);
    setToken(accessToken);
    setUser(userProfile);
    return userProfile;
  }, []);

  const logout = useCallback(async () => {
    if (!isDockerEnv()) {
      try {
        const devData = await apiDevLogin();
        setStoredToken(devData.access_token);
        setToken(devData.access_token);
        setUser(devData.user);
      } catch {
        setToken("dev-bypass-token");
        setUser(DEV_ADMIN_USER);
      }
      setAuthError(null);
      setPermissionNotice(null);
      return;
    }

    removeStoredToken();
    setToken(null);
    setUser(null);
    setAuthError(null);
    setPermissionNotice(null);
  }, []);

  const clearPermissionNotice = useCallback(() => {
    setPermissionNotice(null);
  }, []);

  const clearAuthError = useCallback(() => {
    setAuthError(null);
  }, []);

  // Hierarchical RBAC helpers (for UI rendering only — backend remains authoritative)
  const isSecurityAnalyst = useMemo(() => {
    return Boolean(user && ["Security Analyst", "GRC Reviewer", "Administrator"].includes(user.role));
  }, [user]);

  const isReviewer = useMemo(() => {
    return Boolean(user && ["GRC Reviewer", "Administrator"].includes(user.role));
  }, [user]);

  const isAdmin = useMemo(() => {
    return Boolean(user && user.role === "Administrator");
  }, [user]);

  const value = useMemo(
    () => ({
      isAuthenticated: Boolean(token && user),
      isLoading,
      token,
      user,
      authError,
      permissionNotice,
      login,
      logout,
      clearPermissionNotice,
      clearAuthError,
      isSecurityAnalyst,
      isReviewer,
      isAdmin,
    }),
    [
      token,
      user,
      isLoading,
      authError,
      permissionNotice,
      login,
      logout,
      clearPermissionNotice,
      clearAuthError,
      isSecurityAnalyst,
      isReviewer,
      isAdmin,
    ]
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
};

