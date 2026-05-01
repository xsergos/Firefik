import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { fetchTemplates, publishTemplate, type PolicyTemplate } from "@/lib/controlPlaneApi";
import { queryKeys } from "@/lib/queryKeys";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { TableLoading, TableError } from "@/components/shared/TableStates";
import { toast } from "sonner";

export default function TemplatesPage() {
  const qc = useQueryClient();
  const { data, isLoading, isError, error } = useQuery({
    queryKey: queryKeys.templates(),
    queryFn: () => fetchTemplates(),
  });

  const [name, setName] = useState("");
  const [body, setBody] = useState("");

  const publish = useMutation({
    mutationFn: () => publishTemplate({ name: name.trim(), body }),
    onSuccess: () => {
      toast.success("Template published");
      setName("");
      setBody("");
      qc.invalidateQueries({ queryKey: queryKeys.templates() });
    },
    onError: (e: Error) => toast.error(e.message),
  });

  return (
    <div className="space-y-4">
      <Card>
        <CardHeader>
          <CardTitle>Policy templates (fleet-wide)</CardTitle>
        </CardHeader>
        <CardContent>
          {isLoading && <TableLoading />}
          {isError && <TableError label={(error as Error).message} />}
          {!isLoading && !isError && (data ?? []).length === 0 && (
            <p className="text-sm text-muted-foreground">No templates published yet.</p>
          )}
          {!isLoading && !isError && (data ?? []).length > 0 && (
            <table className="w-full text-sm">
              <thead>
                <tr className="text-left text-muted-foreground">
                  <th className="py-2">Name</th>
                  <th>Version</th>
                  <th>Publisher</th>
                  <th>Updated</th>
                  <th>Labels</th>
                </tr>
              </thead>
              <tbody>
                {(data as PolicyTemplate[]).map((t) => (
                  <tr key={t.name} className="border-t">
                    <td className="py-2 font-mono">{t.name}</td>
                    <td>{t.version}</td>
                    <td className="font-mono text-xs">{t.publisher || "—"}</td>
                    <td className="text-xs">{new Date(t.updated_at).toLocaleString()}</td>
                    <td>
                      {t.labels &&
                        Object.entries(t.labels).map(([k, v]) => (
                          <Badge key={k} variant="secondary" className="mr-1">
                            {k}={v}
                          </Badge>
                        ))}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Publish new template</CardTitle>
        </CardHeader>
        <CardContent className="space-y-3">
          <input
            type="text"
            placeholder="template-name"
            className="w-full rounded border px-3 py-2 font-mono text-sm"
            value={name}
            onChange={(e) => setName(e.target.value)}
          />
          <textarea
            placeholder="policy DSL body…"
            className="h-48 w-full rounded border px-3 py-2 font-mono text-sm"
            value={body}
            onChange={(e) => setBody(e.target.value)}
          />
          <Button
            onClick={() => publish.mutate()}
            disabled={!name.trim() || !body.trim() || publish.isPending}
          >
            {publish.isPending ? "Publishing…" : "Publish"}
          </Button>
        </CardContent>
      </Card>
    </div>
  );
}
