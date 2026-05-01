import { useQuery } from "@tanstack/react-query";
import { fetchRules } from "@/lib/api";
import { queryKeys } from "@/lib/queryKeys";
import type { RuleEntry, FirewallRuleSetDTO } from "@/types/api";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { TableLoading, TableError } from "@/components/shared/TableStates";

export default function RulesPage() {
  const { data, isLoading, isFetching, isError } = useQuery({
    queryKey: queryKeys.rules(),
    queryFn: ({ signal }) => fetchRules({ signal }),
    refetchInterval: 15_000,
  });

  if (isLoading) return <TableLoading label="Loading rules…" />;
  if (isError) return <TableError label="Failed to load rules." />;
  if (!data || data.length === 0)
    return (
      <p className="text-muted-foreground">
        No active firewall rules. Start a container with{" "}
        <code className="text-xs bg-muted px-1 py-0.5 rounded">firefik.enable=true</code>.
        See the{" "}
        <a
          className="underline"
          href="https://github.com/anthropics/firefik#docker-labels"
          target="_blank"
          rel="noopener noreferrer"
        >
          docs
        </a>{" "}
        for label reference.
      </p>
    );

  return (
    <div className="space-y-6" aria-busy={isFetching}>
      <h1 className="text-2xl font-semibold">Active Rules</h1>
      {data.map((entry) => (
        <ContainerRuleCard key={entry.containerID} entry={entry} />
      ))}
    </div>
  );
}

function ContainerRuleCard({ entry }: { entry: RuleEntry }) {
  return (
    <Card>
      <CardHeader className="pb-2">
        <CardTitle className="flex items-center gap-3 text-base">
          <span className="font-mono">{entry.containerName || entry.containerID}</span>
          <Badge variant="outline" className="text-xs font-normal">
            {entry.containerID}
          </Badge>
          <Badge variant={entry.defaultPolicy === "DROP" ? "destructive" : "secondary"}>
            {entry.defaultPolicy}
          </Badge>
          {entry.status && (
            <Badge
              variant={entry.status === "running" ? "default" : "secondary"}
              className="ml-auto text-xs"
            >
              {entry.status}
            </Badge>
          )}
        </CardTitle>
      </CardHeader>
      <CardContent>
        {entry.ruleSets.length === 0 ? (
          <p className="text-sm text-muted-foreground">No rule sets.</p>
        ) : (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Name</TableHead>
                <TableHead>Ports</TableHead>
                <TableHead>Protocol</TableHead>
                <TableHead>Allowlist</TableHead>
                <TableHead>Blocklist</TableHead>
                <TableHead>Profile</TableHead>
                <TableHead>Flags</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {entry.ruleSets.map((rs) => (
                <RuleSetRow key={rs.name} rs={rs} />
              ))}
            </TableBody>
          </Table>
        )}
      </CardContent>
    </Card>
  );
}

function RuleSetRow({ rs }: { rs: FirewallRuleSetDTO }) {
  return (
    <TableRow>
      <TableCell className="font-medium">{rs.name}</TableCell>
      <TableCell>
        {rs.ports?.length ? rs.ports.join(", ") : <span className="text-muted-foreground">any</span>}
      </TableCell>
      <TableCell>
        <Badge variant="outline">{(rs.protocol || "TCP").toUpperCase()}</Badge>
      </TableCell>
      <TableCell>
        <CIDRList items={rs.allowlist} />
      </TableCell>
      <TableCell>
        <CIDRList items={rs.blocklist} variant="destructive" />
      </TableCell>
      <TableCell>
        {rs.profile ? <Badge variant="secondary">{rs.profile}</Badge> : "—"}
      </TableCell>
      <TableCell className="space-x-1">
        {rs.log && <Badge variant="outline">log</Badge>}
        {rs.rateLimit && (
          <Badge variant="outline">
            {rs.rateLimit.rate}/s
          </Badge>
        )}
        {rs.geoBlock && rs.geoBlock.length > 0 && (
          <Badge variant="destructive">block:{rs.geoBlock.join(",")}</Badge>
        )}
        {rs.geoAllow && rs.geoAllow.length > 0 && (
          <Badge variant="default">allow:{rs.geoAllow.join(",")}</Badge>
        )}
      </TableCell>
    </TableRow>
  );
}

function CIDRList({
  items,
  variant = "secondary",
}: {
  items?: string[];
  variant?: "secondary" | "destructive";
}) {
  if (!items || items.length === 0)
    return <span className="text-muted-foreground">—</span>;
  if (items.length <= 3)
    return (
      <div className="flex flex-wrap gap-1">
        {items.map((ip) => (
          <Badge key={ip} variant={variant} className="font-mono text-xs">
            {ip}
          </Badge>
        ))}
      </div>
    );
  return (
    <div className="flex flex-wrap gap-1">
      {items.slice(0, 2).map((ip) => (
        <Badge key={ip} variant={variant} className="font-mono text-xs">
          {ip}
        </Badge>
      ))}
      <Badge variant="outline" className="text-xs">
        +{items.length - 2} more
      </Badge>
    </div>
  );
}
