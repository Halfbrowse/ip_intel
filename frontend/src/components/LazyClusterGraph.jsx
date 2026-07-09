import { lazy, Suspense } from "react";

import { LoadingState } from "./primitives.jsx";

const ClusterGraph = lazy(() => import("./ClusterGraph.jsx"));

export default function LazyClusterGraph(props) {
  return (
    <Suspense fallback={<LoadingState message="Loading graph tools..." />}>
      <ClusterGraph {...props} />
    </Suspense>
  );
}
