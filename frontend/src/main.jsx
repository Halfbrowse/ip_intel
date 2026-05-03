import ReactDOM from "react-dom/client";

import App from "./App.jsx";
import { BrowserRouter } from "./router.jsx";
import "./styles.css";

ReactDOM.createRoot(document.getElementById("root")).render(
  <BrowserRouter>
    <App />
  </BrowserRouter>,
);
