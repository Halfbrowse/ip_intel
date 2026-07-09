const FOCUS_KEY = "ipintel.focus";

export function rememberFocus(domains) {
  const list = Array.isArray(domains) ? domains : [domains];
  try {
    window.sessionStorage.setItem(FOCUS_KEY, JSON.stringify(list.filter(Boolean)));
  } catch {
    // Best-effort; navigation still works without a pre-selected channel.
  }
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
