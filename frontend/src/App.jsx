import { Route, Routes } from "./router.jsx";
import ClustersPage from "./pages/ClustersPage.jsx";
import ConnectionsPage from "./pages/ConnectionsPage.jsx";
import DomainPage from "./pages/DomainPage.jsx";
import NotFoundPage from "./pages/NotFoundPage.jsx";
import PoolPage from "./pages/PoolPage.jsx";

export { getInitialTheme, ThemeProvider } from "./shell/AppShell.jsx";

export default function App() {
  return (
    <Routes>
      <Route path="/" element={<PoolPage />} />
      <Route path="/domain/:value" element={<DomainPage />} />
      <Route path="/connections" element={<ConnectionsPage />} />
      <Route path="/clusters" element={<ClustersPage />} />
      <Route path="*" element={<NotFoundPage />} />
    </Routes>
  );
}
