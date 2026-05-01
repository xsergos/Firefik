import { BrowserRouter, Routes, Route } from "react-router-dom";
import { QueryClientProvider } from "@tanstack/react-query";
import { ThemeProvider } from "next-themes";
import { queryClient } from "@/lib/queryClient";
import { AppShell } from "@/components/layout/AppShell";
import { ErrorBoundary } from "@/components/ErrorBoundary";
import { Toaster } from "@/components/ui/sonner";
import DashboardPage from "@/pages/DashboardPage";
import ContainersPage from "@/pages/ContainersPage";
import RulesPage from "@/pages/RulesPage";
import LogsPage from "@/pages/LogsPage";
import HistoryPage from "@/pages/HistoryPage";
import PoliciesPage from "@/pages/PoliciesPage";
import ProposalsPage from "@/pages/ProposalsPage";
import TemplatesPage from "@/pages/TemplatesPage";
import ApprovalsPage from "@/pages/ApprovalsPage";

export default function App() {
  return (
    <ThemeProvider attribute="class" defaultTheme="system" enableSystem>
      <QueryClientProvider client={queryClient}>
        <BrowserRouter>
          <Routes>
            <Route element={<AppShell />}>
              <Route index element={<ErrorBoundary><DashboardPage /></ErrorBoundary>} />
              <Route path="containers" element={<ErrorBoundary><ContainersPage /></ErrorBoundary>} />
              <Route path="rules" element={<ErrorBoundary><RulesPage /></ErrorBoundary>} />
              <Route path="logs" element={<ErrorBoundary><LogsPage /></ErrorBoundary>} />
              <Route path="history" element={<ErrorBoundary><HistoryPage /></ErrorBoundary>} />
              <Route path="policies" element={<ErrorBoundary><PoliciesPage /></ErrorBoundary>} />
              <Route path="proposals" element={<ErrorBoundary><ProposalsPage /></ErrorBoundary>} />
              <Route path="templates" element={<ErrorBoundary><TemplatesPage /></ErrorBoundary>} />
              <Route path="approvals" element={<ErrorBoundary><ApprovalsPage /></ErrorBoundary>} />
            </Route>
          </Routes>
        </BrowserRouter>
        <Toaster />
      </QueryClientProvider>
    </ThemeProvider>
  );
}
