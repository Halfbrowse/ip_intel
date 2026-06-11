import ReactDOM from "react-dom/client";

import App, { getInitialTheme } from "./App.jsx";
import { BrowserRouter } from "./router.jsx";
import "./styles.css";

// Apply the persisted (or system-preferred) theme before the first paint so the
// page does not flash the light palette for dark-theme users.
document.documentElement.setAttribute("data-theme", getInitialTheme());

ReactDOM.createRoot(document.getElementById("root")).render(
  <BrowserRouter>
    <App />
  </BrowserRouter>,
);
