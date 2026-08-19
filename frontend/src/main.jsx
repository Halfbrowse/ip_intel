import ReactDOM from "react-dom/client";

import App, { getInitialTheme, ThemeProvider } from "./App.jsx";
import ErrorBoundary from "./components/ErrorBoundary.jsx";
import { BrowserRouter } from "./router.jsx";
import "reshaped/themes/slate/theme.css";
import "./reshaped-theme.css";
import "./styles.css";

// Apply the persisted (or system-preferred) theme before the first paint so
// the page does not flash the light palette for dark-theme users. ThemeProvider
// (in AppShell.jsx) re-applies both attributes reactively on every toggle and
// drives Reshaped's own colorMode context (needed for portaled content like
// the search Autocomplete's dropdown) -- this is just the pre-mount value.
const initialTheme = getInitialTheme();
document.documentElement.setAttribute("data-theme", initialTheme);
document.documentElement.setAttribute("data-rs-color-mode", initialTheme);

ReactDOM.createRoot(document.getElementById("root")).render(
  <BrowserRouter>
    <ThemeProvider>
      <ErrorBoundary title="The app hit an unexpected error">
        <App />
      </ErrorBoundary>
    </ThemeProvider>
  </BrowserRouter>,
);
