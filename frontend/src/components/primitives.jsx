import { Alert, Card, Loader, ProgressBar as ReshapedProgressBar, Text, View } from "reshaped";

export function MetricCard({ label, value }) {
  return (
    <Card padding={4}>
      <View gap={1}>
        <Text color="neutral-faded" variant="caption-1">
          {label}
        </Text>
        <Text variant="featured-3" weight="bold">
          {value}
        </Text>
      </View>
    </Card>
  );
}

export function InlineMetric({ label, value }) {
  return (
    <View align="center" direction="row" gap={2}>
      <Text color="neutral-faded" variant="body-2">
        {label}
      </Text>
      <Text variant="body-2" weight="bold">
        {value}
      </Text>
    </View>
  );
}

export function ProgressBar({ large = false, value }) {
  const safeValue = Number.isFinite(value) ? Math.max(0, Math.min(100, value)) : 0;
  return <ReshapedProgressBar color="primary" size={large ? "medium" : "small"} value={safeValue} />;
}

export function LoadingState({ message }) {
  return (
    <View align="center" direction="row" gap={2} padding={4}>
      <Loader color="primary" size="small" />
      <Text color="neutral-faded">{message}</Text>
    </View>
  );
}

export function ErrorState({ message }) {
  return <Alert color="critical">{message}</Alert>;
}

export function EmptyState({ message }) {
  return (
    <Card padding={4}>
      <Text color="neutral-faded">{message}</Text>
    </Card>
  );
}
