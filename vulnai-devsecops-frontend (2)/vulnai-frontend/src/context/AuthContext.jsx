import { createContext, useContext, useEffect, useState } from "react";
import { currentUser } from "../data/mockData";
import api from "../lib/api";

const AuthContext = createContext(null);

function getStoredToken() {
  const token = localStorage.getItem("token");
  if (token?.startsWith("mock_token_")) {
    localStorage.removeItem("token");
    return null;
  }
  return token;
}

export function AuthProvider({ children }) {
  const [isAuthenticated, setIsAuthenticated] = useState(() => Boolean(getStoredToken()));
  const [user, setUser] = useState(() => (getStoredToken() ? currentUser : null));

  useEffect(() => {
    function handleUnauthorized() {
      setIsAuthenticated(false);
      setUser(null);
    }

    window.addEventListener("auth:logout", handleUnauthorized);
    return () => window.removeEventListener("auth:logout", handleUnauthorized);
  }, []);

  async function login(email, password) {
    const response = await api.post("/auth/login", { email, password });
    localStorage.setItem("token", response.data.access_token);
    setUser({ ...currentUser, email: email || currentUser.email });
    setIsAuthenticated(true);
  }

  function logout() {
    localStorage.removeItem("token");
    setIsAuthenticated(false);
    setUser(null);
  }

  return (
    <AuthContext.Provider value={{ isAuthenticated, user, login, logout }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used within AuthProvider");
  return ctx;
}
