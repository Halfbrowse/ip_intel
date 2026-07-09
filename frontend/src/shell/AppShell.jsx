import { useEffect, useState } from "react";

import { Link, NavLink } from "../router.jsx";

const THEME_STORAGE_KEY = "theme";

const NAV_ITEMS = [
  { to: "/", label: "Pool" },
  { to: "/connections", label: "Connections" },
  { to: "/clusters", label: "Clusters" },
];

export function getInitialTheme() {
  try {
    const stored = window.localStorage.getItem(THEME_STORAGE_KEY);
    if (stored === "light" || stored === "dark") {
      return stored;
    }
  } catch {
    // Ignore storage errors and fall back to the system preference.
  }
  return window.matchMedia?.("(prefers-color-scheme: dark)")?.matches ? "dark" : "light";
}

function useTheme() {
  const [theme, setTheme] = useState(getInitialTheme);

  useEffect(() => {
    document.documentElement.setAttribute("data-theme", theme);
  }, [theme]);

  const toggleTheme = () => {
    const next = theme === "dark" ? "light" : "dark";
    try {
      window.localStorage.setItem(THEME_STORAGE_KEY, next);
    } catch {
      // Best-effort persistence.
    }
    setTheme(next);
  };

  return { theme, toggleTheme };
}

export default function AppShell({ children }) {
  const { theme, toggleTheme } = useTheme();

  return (
    <div className="app-shell">
      <header className="app-header">
        <Link className="brand-mark" to="/">
          <span>IP</span>
          <strong>Intel</strong>
        </Link>
        <nav className="app-nav" aria-label="Sections">
          {NAV_ITEMS.map((item) => (
            <NavLink
              className={({ isActive }) => (isActive ? "app-nav-link active" : "app-nav-link")}
              key={item.to}
              to={item.to}
            >
              {item.label}
            </NavLink>
          ))}
        </nav>
        <div className="header-side">
          <button
            aria-pressed={theme === "dark"}
            className="secondary-button theme-toggle"
            onClick={toggleTheme}
            title={theme === "dark" ? "Switch to the light theme" : "Switch to the dark theme"}
            type="button"
          >
            <span aria-hidden="true" className="theme-toggle-indicator" />
            {theme === "dark" ? "Light mode" : "Dark mode"}
          </button>
        </div>
      </header>
      <main className="app-main">{children}</main>
    </div>
  );
}
