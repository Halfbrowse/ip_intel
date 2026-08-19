const FOCUS_KEY = "ipintel.focus";

// Channels handed to the connections page by something else — the global
// search box picking a selector, a "compare these" link. sessionStorage is the
// carrier so the pick survives the navigation, but a store that is only read
// once at mount is not enough on its own: when the user is *already* on
// /connections, the router's navigate() is a no-op for the current path, the
// page never remounts, and the pick would sit in storage until some later
// visit surfaced it as a mystery pre-selection. Subscribers close that gap.
const subscribers = new Set();

export function rememberFocus(domains) {
  const list = (Array.isArray(domains) ? domains : [domains]).filter(Boolean);
  try {
    window.sessionStorage.setItem(FOCUS_KEY, JSON.stringify(list));
  } catch {
    // Best-effort; navigation still works without a pre-selected channel.
  }
  // Notify after the write, so a subscriber that chooses to drain via
  // takeFocus() sees the value rather than racing it.
  subscribers.forEach((listener) => {
    try {
      listener(list);
    } catch {
      // A broken listener must not prevent navigation.
    }
  });
}

export function takeFocus() {
  try {
    const raw = window.sessionStorage.getItem(FOCUS_KEY);
    if (raw) {
      window.sessionStorage.removeItem(FOCUS_KEY);
    }
    if (!raw) {
      return [];
    }
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed.filter(Boolean) : [String(parsed)];
  } catch {
    return [];
  }
}

// Returns an unsubscribe function, so callers can use it directly as a
// useEffect cleanup.
export function subscribeFocus(listener) {
  subscribers.add(listener);
  return () => {
    subscribers.delete(listener);
  };
}
