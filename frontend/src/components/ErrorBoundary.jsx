import { Component } from "react";

// A render throw anywhere below this point used to unmount the entire tool and
// leave a blank page with nothing in the UI to say why — an analyst mid-triage
// would just lose the app. React only supports class components for this.
//
// Deliberately not a full-page takeover when used around a subtree: wrap the
// graph on its own and the rest of the page keeps working.
export default class ErrorBoundary extends Component {
  constructor(props) {
    super(props);
    this.state = { error: null };
  }

  static getDerivedStateFromError(error) {
    return { error };
  }

  componentDidCatch(error, info) {
    // Keep the stack in the console; there is no error-reporting backend here.
    console.error("Render error:", error, info?.componentStack);
  }

  render() {
    const { error } = this.state;
    if (!error) {
      return this.props.children;
    }

    return (
      <div className="panel section-stack" role="alert">
        <h2>{this.props.title || "Something went wrong"}</h2>
        <p className="section-copy">
          This part of the page failed to render. The data it was given may be in an unexpected
          shape — reload to try again, and check the browser console for the details.
        </p>
        <pre className="error-detail">{String(error?.message || error)}</pre>
        <div className="action-row">
          <button className="primary-button" onClick={() => this.setState({ error: null })} type="button">
            Try again
          </button>
          <button className="secondary-button" onClick={() => window.location.reload()} type="button">
            Reload the page
          </button>
        </div>
      </div>
    );
  }
}
