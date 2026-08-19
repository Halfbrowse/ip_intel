import { createContext, useContext, useEffect, useState } from "react";
import { Button, Reshaped, Text, View } from "reshaped";

import { Link, NavLink } from "../router.jsx";
import SearchBox from "./SearchBox.jsx";

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

// Theme state lives at the app root (see ThemeProvider below, mounted once in
// main.jsx) rather than inside AppShell itself, because Reshaped's own
// color-mode context needs the value at the SAME level as the <Reshaped>
// provider to correctly theme portaled content (Autocomplete/DropdownMenu/
// Modal, which render outside AppShell's own DOM subtree via React portals).
// Passing colorMode as a controlled prop -- not just toggling a DOM attribute
// after the fact -- is what makes those portals pick up the right palette.
const ThemeContext = createContext({ theme: "light", toggleTheme: () => {} });

export function ThemeProvider({ children }) {
  const [theme, setTheme] = useState(getInitialTheme);

  useEffect(() => {
    // Drives styles.css's :root[data-theme="dark"] block (everything not yet
    // on a Reshaped component, chiefly ClusterGraph.jsx's SVG).
    document.documentElement.setAttribute("data-theme", theme);
    // Reshaped's own root color-mode effect only sets data-rs-color-mode
    // once (it no-ops on later renders once *anything* is present -- see
    // reshaped's PrivateTheme component), so it never picks up later
    // toggles on its own. Setting it here unconditionally on every change
    // is what actually makes the toggle work for non-portaled content; the
    // colorMode prop below (context-driven) is what makes it work for
    // portaled content (Autocomplete/DropdownMenu/Modal), which read the
    // color mode from React context rather than this DOM attribute.
    document.documentElement.setAttribute("data-rs-color-mode", theme);
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

  return (
    <ThemeContext.Provider value={{ theme, toggleTheme }}>
      <Reshaped colorMode={theme} theme="slate">
        {children}
      </Reshaped>
    </ThemeContext.Provider>
  );
}

function useTheme() {
  return useContext(ThemeContext);
}

export default function AppShell({ children }) {
  const { theme, toggleTheme } = useTheme();

  return (
    <div className="app-shell">
      <header className="app-header">
        <Link className="brand-mark" to="/">
          <Text as="span" variant="body-1" weight="bold">
            IP
          </Text>
          <Text as="span" variant="body-1" weight="extrabold">
            Intel
          </Text>
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
        <View align="center" direction="row" gap={3}>
          <SearchBox />
          <Button
            attributes={{ "aria-pressed": theme === "dark" }}
            onClick={toggleTheme}
            title={theme === "dark" ? "Switch to the light theme" : "Switch to the dark theme"}
            variant="outline"
          >
            {theme === "dark" ? "Light mode" : "Dark mode"}
          </Button>
        </View>
      </header>
      <main className="app-main">{children}</main>
    </div>
  );
}
