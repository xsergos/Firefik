import { useMemo } from "react";
import { useQuery } from "@tanstack/react-query";
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  Legend,
} from "recharts";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { fetchStats } from "@/lib/api";
import { queryKeys } from "@/lib/queryKeys";
import type { StatsResponse } from "@/types/api";
import { TableLoading, TableError } from "@/components/shared/TableStates";

function useStats() {
  return useQuery<StatsResponse>({
    queryKey: queryKeys.stats(),
    queryFn: ({ signal }) => fetchStats({ signal }),
    refetchInterval: 15_000,
  });
}

const MAX_POINTS = 300;

function downsample(points: StatsResponse["traffic"]): StatsResponse["traffic"] {
  if (points.length <= MAX_POINTS) return points;
  const bucketSize = Math.ceil(points.length / MAX_POINTS);
  const out: StatsResponse["traffic"] = [];
  for (let i = 0; i < points.length; i += bucketSize) {
    const slice = points.slice(i, i + bucketSize);
    let accepted = 0;
    let dropped = 0;
    for (const p of slice) {
      accepted += p.accepted;
      dropped += p.dropped;
    }
    const first = slice[0];
    if (!first) continue;
    out.push({ ts: first.ts, accepted, dropped });
  }
  return out;
}

export default function DashboardPage() {
  const { data, isLoading, isError } = useStats();

  const traffic = useMemo(
    () => (data?.traffic ? downsample(data.traffic) : []),
    [data],
  );

  if (isError)
    return (
      <TableError label="Failed to load dashboard stats. Make sure the backend is running." />
    );

  const total = data?.containers.total ?? 0;
  const running = data?.containers.running ?? 0;
  const enabled = data?.containers.enabled ?? 0;

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold">Dashboard</h1>

      <div className="grid gap-4 grid-cols-1 sm:grid-cols-3">
        <StatCard title="Total containers" value={isLoading ? "…" : String(total)} />
        <StatCard title="Running" value={isLoading ? "…" : String(running)} />
        <StatCard title="Firewall enabled" value={isLoading ? "…" : String(enabled)} />
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Traffic (last 60 min)</CardTitle>
        </CardHeader>
        <CardContent>
          {isLoading ? (
            <TableLoading label="Loading traffic data…" />
          ) : traffic.length > 0 ? (
            <ResponsiveContainer width="100%" height={220}>
              <AreaChart data={traffic} margin={{ top: 4, right: 8, left: 0, bottom: 0 }}>
                <defs>
                  <linearGradient id="colorAccepted" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#22c55e" stopOpacity={0.25} />
                    <stop offset="95%" stopColor="#22c55e" stopOpacity={0} />
                  </linearGradient>
                  <linearGradient id="colorDropped" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#ef4444" stopOpacity={0.25} />
                    <stop offset="95%" stopColor="#ef4444" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <XAxis
                  dataKey="ts"
                  tickFormatter={(v: string) => new Date(v).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}
                  tick={{ fontSize: 11 }}
                  minTickGap={40}
                />
                <YAxis tick={{ fontSize: 11 }} width={32} />
                <Tooltip
                  labelFormatter={(v) => typeof v === "string" && v ? new Date(v).toLocaleTimeString() : ""}
                  formatter={(value, name) => [value, name === "accepted" ? "Accepted" : "Dropped"]}
                />
                <Legend formatter={(v) => (v === "accepted" ? "Accepted" : "Dropped")} />
                <Area
                  type="monotone"
                  dataKey="accepted"
                  stroke="#22c55e"
                  strokeWidth={2}
                  fill="url(#colorAccepted)"
                  dot={false}
                />
                <Area
                  type="monotone"
                  dataKey="dropped"
                  stroke="#ef4444"
                  strokeWidth={2}
                  fill="url(#colorDropped)"
                  dot={false}
                />
              </AreaChart>
            </ResponsiveContainer>
          ) : (
            <p className="text-sm text-muted-foreground py-10 text-center">
              No traffic data yet. Firewall events will appear here.
            </p>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

function StatCard({ title, value }: { title: string; value: string }) {
  return (
    <Card>
      <CardHeader className="pb-2">
        <CardTitle className="text-sm font-medium text-muted-foreground">{title}</CardTitle>
      </CardHeader>
      <CardContent>
        <p className="text-3xl font-bold">{value}</p>
      </CardContent>
    </Card>
  );
}