import {
  Children,
  createContext,
  isValidElement,
  useContext,
  useEffect,
  useState,
} from "react";

const RouterContext = createContext(null);
const RouteContext = createContext({
  outlet: null,
  params: {},
  pathnameBase: "/",
});
const OutletContext = createContext(undefined);

export function BrowserRouter({ children }) {
  const [pathname, setPathname] = useState(() => window.location.pathname || "/");

  useEffect(() => {
    const onPopState = () => {
      setPathname(window.location.pathname || "/");
    };

    window.addEventListener("popstate", onPopState);
    return () => {
      window.removeEventListener("popstate", onPopState);
    };
  }, []);

  const routerValue = {
    pathname,
    navigate(to, options = {}) {
      const nextPath = normalizePath(to);

      if (nextPath === pathname) {
        return;
      }

      if (options.replace) {
        window.history.replaceState({}, "", nextPath);
      } else {
        window.history.pushState({}, "", nextPath);
      }

      setPathname(nextPath);
    },
  };

  return <RouterContext.Provider value={routerValue}>{children}</RouterContext.Provider>;
}

export function Routes({ children }) {
  const router = useContext(RouterContext);
  const branches = createBranches(createRouteObjects(children));
  const match = branches.find((branch) => matchesPath(branch.path, router.pathname));

  if (!match) {
    return null;
  }

  const params = matchesPath(match.path, router.pathname) || {};
  return renderBranch(match, params, router.pathname);
}

export function Route() {
  return null;
}

export function Navigate({ replace = false, to }) {
  const router = useContext(RouterContext);
  const route = useContext(RouteContext);

  useEffect(() => {
    router.navigate(resolveTo(to, route.pathnameBase), { replace });
  }, [replace, route.pathnameBase, router, to]);

  return null;
}

export function Link({ children, onClick, to, ...rest }) {
  const router = useContext(RouterContext);
  const route = useContext(RouteContext);
  const href = resolveTo(to, route.pathnameBase);

  return (
    <a
      {...rest}
      href={href}
      onClick={(event) => {
        onClick?.(event);

        if (
          event.defaultPrevented ||
          event.button !== 0 ||
          event.metaKey ||
          event.altKey ||
          event.ctrlKey ||
          event.shiftKey
        ) {
          return;
        }

        event.preventDefault();
        router.navigate(href);
      }}
    >
      {children}
    </a>
  );
}

export function NavLink({ children, className, to, ...rest }) {
  const router = useContext(RouterContext);
  const route = useContext(RouteContext);
  const href = resolveTo(to, route.pathnameBase);
  const isActive = router.pathname === href;
  const resolvedClassName =
    typeof className === "function" ? className({ isActive }) : className;

  return (
    <Link {...rest} className={resolvedClassName} to={href}>
      {typeof children === "function" ? children({ isActive }) : children}
    </Link>
  );
}

export function Outlet({ context }) {
  const route = useContext(RouteContext);

  if (!route.outlet) {
    return null;
  }

  return <OutletContext.Provider value={context}>{route.outlet}</OutletContext.Provider>;
}

export function useOutletContext() {
  return useContext(OutletContext);
}

export function useParams() {
  return useContext(RouteContext).params;
}

export function useNavigate() {
  const router = useContext(RouterContext);
  return (to, options) => router.navigate(to, options);
}

function createRouteObjects(children) {
  return Children.toArray(children)
    .filter((child) => isValidElement(child))
    .map((child) => ({
      children: createRouteObjects(child.props.children),
      element: child.props.element ?? null,
      index: Boolean(child.props.index),
      path: child.props.path ?? null,
    }));
}

function createBranches(routes, parentPath = "", parentChain = []) {
  const branches = [];

  routes.forEach((route) => {
    const fullPath = route.index ? parentPath || "/" : joinPaths(parentPath, route.path);
    const chain = [...parentChain, { ...route, fullPath, parentPath }];

    if (route.children.length > 0) {
      branches.push(...createBranches(route.children, fullPath, chain));
    }

    if (route.index || route.children.length === 0) {
      branches.push({ chain, path: fullPath || "/" });
    }
  });

  return branches;
}

function renderBranch(branch, params, pathname) {
  let outlet = null;

  for (let index = branch.chain.length - 1; index >= 0; index -= 1) {
    const route = branch.chain[index];
    const pathnameBase = materializePath(
      route.index ? route.parentPath || "/" : route.fullPath,
      params,
      pathname,
    );

    const element = route.element || outlet;

    outlet = (
      <RouteContext.Provider
        value={{
          outlet,
          params,
          pathnameBase,
        }}
      >
        {element}
      </RouteContext.Provider>
    );
  }

  return outlet;
}

function matchesPath(pattern, pathname) {
  if (pattern === "*") {
    return {};
  }

  const patternSegments = splitPath(pattern);
  const pathnameSegments = splitPath(pathname);

  if (patternSegments.length !== pathnameSegments.length) {
    return null;
  }

  const params = {};

  for (let index = 0; index < patternSegments.length; index += 1) {
    const patternSegment = patternSegments[index];
    const pathnameSegment = pathnameSegments[index];

    if (patternSegment === "*") {
      return params;
    }

    if (patternSegment.startsWith(":")) {
      params[patternSegment.slice(1)] = decodeURIComponent(pathnameSegment);
      continue;
    }

    if (patternSegment !== pathnameSegment) {
      return null;
    }
  }

  return params;
}

function materializePath(pattern, params, fallbackPath) {
  if (!pattern || pattern === "*") {
    return fallbackPath;
  }

  const segments = splitPath(pattern).map((segment) =>
    segment.startsWith(":") ? params[segment.slice(1)] || segment : segment,
  );

  return normalizePath(`/${segments.join("/")}`);
}

function joinPaths(parentPath, childPath) {
  if (!childPath || childPath === ".") {
    return parentPath || "/";
  }

  if (childPath === "*") {
    return "*";
  }

  if (childPath.startsWith("/")) {
    return normalizePath(childPath);
  }

  return normalizePath(`${parentPath || ""}/${childPath}`);
}

function resolveTo(to, pathnameBase) {
  if (!to) {
    return pathnameBase || "/";
  }

  if (to.startsWith("/")) {
    return normalizePath(to);
  }

  return normalizePath(`${pathnameBase || "/"}/${to}`);
}

function splitPath(pathname) {
  if (!pathname || pathname === "/") {
    return [];
  }

  return normalizePath(pathname)
    .split("/")
    .filter(Boolean);
}

function normalizePath(pathname) {
  const normalized = pathname.replace(/\/+/g, "/");
  return normalized === "/" ? normalized : normalized.replace(/\/$/, "");
}
