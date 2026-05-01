import { useQuery } from "@tanstack/react-query";
import { fetchContainers } from "@/lib/api";
import { queryKeys } from "@/lib/queryKeys";

export function useContainers() {
  return useQuery({
    queryKey: queryKeys.containers(),
    queryFn: ({ signal }) => fetchContainers({ signal }),
    refetchInterval: 15_000,
  });
}
