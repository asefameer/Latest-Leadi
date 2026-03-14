import { createContext, useContext, useState, useEffect, ReactNode } from "react";

export type UserRole = "admin" | "viewer" | "tso" | "management";

export interface AdminUser {
  id: string;
  role: "admin" | "viewer";
  email: string;
  phone: string;
}

export interface TSOUser {
  id: string;
  role: "tso";
  username: string;
  wing: string;
  division: string;
  territory_code: string;
  territory: string;
}

export interface ManagementUser {
  id: string;
  role: "management";
  display_name: string;
  visibility: "all" | "only own wing" | "only own division";
}

export type User = AdminUser | TSOUser | ManagementUser;

interface AuthContextType {
  isAuthenticated: boolean;
  isAdmin: boolean;
  isLoading: boolean;
  user: User | null;
  login: (email: string, password: string) => Promise<void>;
  loginTSO: (username: string, password: string) => Promise<void>;
  loginManagement: (userId: string, password: string) => Promise<void>;
  signup: (email: string, phone: string, password: string) => Promise<void>;
  logout: () => Promise<void>;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

const AUTH_TOKEN_KEY = "auth_token";

const getApiBaseUrl = () => {
  const envUrl = import.meta.env.VITE_CHATBOT_BACKEND_URL as string | undefined;
  return envUrl || "";
};

const getStoredToken = () => localStorage.getItem(AUTH_TOKEN_KEY);

const setStoredToken = (token: string) => {
  localStorage.setItem(AUTH_TOKEN_KEY, token);
};

const clearStoredToken = () => {
  localStorage.removeItem(AUTH_TOKEN_KEY);
  localStorage.removeItem("userId");
};

async function apiRequest<T>(path: string, options: RequestInit = {}, token?: string): Promise<T> {
  const headers = new Headers(options.headers || {});
  headers.set("Content-Type", "application/json");

  if (token) {
    headers.set("Authorization", `Bearer ${token}`);
  }

  const response = await fetch(`${getApiBaseUrl()}${path}`, {
    ...options,
    headers,
  });

  const contentType = response.headers.get("Content-Type") || "";
  const data = contentType.includes("application/json") ? await response.json() : null;

  if (!response.ok) {
    throw new Error(data?.error || `Request failed with status ${response.status}`);
  }

  return data as T;
}

export const AuthProvider = ({ children }: { children: ReactNode }) => {
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [user, setUser] = useState<User | null>(null);
  const [isLoading, setIsLoading] = useState(true);

  const isAdmin = user?.role === "admin";

  const applyAuthenticatedState = (nextUser: User, token: string) => {
    setStoredToken(token);
    localStorage.setItem("userId", nextUser.id);
    setIsAuthenticated(true);
    setUser(nextUser);
  };

  const loginTSO = async (username: string, password: string) => {
    const response = await apiRequest<{ token: string; user: TSOUser }>("/api/auth/tso-login", {
      method: "POST",
      body: JSON.stringify({ username, password }),
    });
    applyAuthenticatedState(response.user, response.token);
  };

  const loginManagement = async (userId: string, password: string) => {
    const response = await apiRequest<{ token: string; user: ManagementUser }>("/api/auth/mgmt-login", {
      method: "POST",
      body: JSON.stringify({ userId, password }),
    });
    applyAuthenticatedState(response.user, response.token);
  };

  useEffect(() => {
    const bootstrapAuth = async () => {
      const token = getStoredToken();
      if (!token) {
        setIsLoading(false);
        return;
      }

      try {
        const response = await apiRequest<{ user: User }>("/api/auth/me", { method: "GET" }, token);
        setIsAuthenticated(true);
        setUser(response.user);
        localStorage.setItem("userId", response.user.id);
      } catch (error) {
        clearStoredToken();
        setIsAuthenticated(false);
        setUser(null);
      } finally {
        setIsLoading(false);
      }
    };

    bootstrapAuth();
  }, []);

  const signup = async (email: string, phone: string, password: string) => {
    const response = await apiRequest<{ token: string; user: User }>("/api/auth/signup", {
      method: "POST",
      body: JSON.stringify({ email, phone, password }),
    });

    applyAuthenticatedState(response.user, response.token);
  };

  const login = async (email: string, password: string) => {
    const response = await apiRequest<{ token: string; user: User }>("/api/auth/login", {
      method: "POST",
      body: JSON.stringify({ email, password }),
    });

    applyAuthenticatedState(response.user, response.token);
  };

  const logout = async () => {
    const token = getStoredToken();
    if (token) {
      try {
        await apiRequest<{ success: boolean }>("/api/auth/logout", { method: "POST" }, token);
      } catch (error) {
        // Ignore logout API errors and clear local session anyway
      }
    }

    setIsAuthenticated(false);
    setUser(null);
    clearStoredToken();
  };

  return (
    <AuthContext.Provider value={{ isAuthenticated, isAdmin, isLoading, user, login, loginTSO, loginManagement, signup, logout }}>
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (context === undefined) {
    throw new Error("useAuth must be used within an AuthProvider");
  }
  return context;
};
