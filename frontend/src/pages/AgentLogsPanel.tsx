import { useEffect, useRef, useState } from "react";

type LogLine = {
  agent: { instance_id: string; hostname: string };
  at: string;
  level?: string;
  source?: string;
  line: string;
  fields?: Record<string, string>;
};

const MAX_LINES = 500;

function wsURL(agentID: string): string {
  const proto = window.location.protocol === "https:" ? "wss:" : "ws:";
  return `${proto}//${window.location.host}/api/agents/${encodeURIComponent(agentID)}/logs`;
}

export function AgentLogsPanel({ agentID }: { agentID: string }) {
  const [lines, setLines] = useState<LogLine[]>([]);
  const [status, setStatus] = useState<"connecting" | "open" | "closed" | "error">("connecting");
  const wsRef = useRef<WebSocket | null>(null);

  useEffect(() => {
    if (!agentID) return;
    const ws = new WebSocket(wsURL(agentID));
    wsRef.current = ws;
    // eslint-disable-next-line react-hooks/set-state-in-effect
    setStatus("connecting");

    ws.onopen = () => setStatus("open");
    ws.onclose = () => setStatus("closed");
    ws.onerror = () => setStatus("error");
    ws.onmessage = (ev) => {
      try {
        const parsed = JSON.parse(ev.data) as LogLine;
        setLines((prev) => {
          const next = [...prev, parsed];
          if (next.length > MAX_LINES) next.splice(0, next.length - MAX_LINES);
          return next;
        });
      } catch {
        /* ignore non-JSON */
      }
    };

    return () => {
      ws.close();
    };
  }, [agentID]);

  return (
    <div className="space-y-2">
      <div className="flex items-center gap-2 text-xs text-muted-foreground">
        <span>WebSocket: {status}</span>
        {lines.length > 0 && <span>{lines.length} lines</span>}
        {lines.length >= MAX_LINES && <span>(rolling buffer)</span>}
      </div>
      <pre className="bg-muted rounded p-3 text-xs max-h-96 overflow-auto font-mono leading-tight">
        {lines.length === 0
          ? "Waiting for log events… only rule sets with log:true emit NFLOG events (e.g. firefik.firewall.web.log=true)"
          : lines
              .map((l) => {
                const ts = new Date(l.at).toISOString();
                const lvl = l.level ? `[${l.level}]` : "";
                const src = l.source ? `${l.source}:` : "";
                return `${ts} ${lvl}${src} ${l.line}`;
              })
              .join("\n")}
      </pre>
    </div>
  );
}
