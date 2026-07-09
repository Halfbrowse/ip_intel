import { Link } from "../router.jsx";
import AppShell from "../shell/AppShell.jsx";

export default function NotFoundPage() {
  return (
    <AppShell>
      <section className="panel section-stack">
        <div className="panel-header">
          <div>
            <p className="eyebrow">404</p>
            <h1>Page not found</h1>
          </div>
        </div>
        <p className="section-copy">This page does not exist.</p>
        <div className="action-row">
          <Link className="primary-button" to="/">
            Back to the pool
          </Link>
        </div>
      </section>
    </AppShell>
  );
}
