import { NavLink, Outlet } from "react-router-dom";
import { useTheme } from "next-themes";
import { Moon, Sun } from "lucide-react";
import { useTranslation } from "react-i18next";
import { cn } from "@/lib/utils";

function ThemeToggle() {
  const { t } = useTranslation();
  const { resolvedTheme, setTheme } = useTheme();
  const isDark = resolvedTheme === "dark";
  return (
    <button
      onClick={() => setTheme(isDark ? "light" : "dark")}
      className="w-full flex items-center gap-2 px-3 py-2 rounded-md text-sm text-muted-foreground hover:bg-accent hover:text-accent-foreground transition-colors"
      aria-label={isDark ? t("theme.switchToLight") : t("theme.switchToDark")}
    >
      {isDark ? <Sun className="h-4 w-4" /> : <Moon className="h-4 w-4" />}
      {isDark ? t("theme.lightMode") : t("theme.darkMode")}
    </button>
  );
}

export function AppShell() {
  const { t } = useTranslation();
  const navItems = [
    { to: "/", label: t("nav.dashboard"), end: true },
    { to: "/containers", label: t("nav.containers") },
    { to: "/rules", label: t("nav.rules") },
    { to: "/policies", label: t("nav.policies") },
    { to: "/proposals", label: t("nav.proposals") },
    { to: "/templates", label: t("nav.templates", "Templates") },
    { to: "/approvals", label: t("nav.approvals", "Approvals") },
    { to: "/logs", label: t("nav.logs") },
    { to: "/history", label: t("nav.history") },
  ];
  return (
    <div className="min-h-screen flex">
      <aside className="w-52 shrink-0 border-r bg-muted/40 flex flex-col">
        <div className="px-6 py-5 border-b">
          <span className="text-lg font-bold tracking-tight">Firefik</span>
        </div>
        <nav className="flex-1 px-3 py-4 space-y-1" aria-label="Main navigation">
          {navItems.map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              end={item.end}
              className={({ isActive }) =>
                cn(
                  "block px-3 py-2 rounded-md text-sm font-medium transition-colors",
                  isActive
                    ? "bg-primary text-primary-foreground"
                    : "text-muted-foreground hover:bg-accent hover:text-accent-foreground"
                )
              }
            >
              {item.label}
            </NavLink>
          ))}
        </nav>
        <div className="px-3 pb-4">
          <ThemeToggle />
        </div>
      </aside>

      <main className="flex-1 overflow-auto p-8">
        <Outlet />
      </main>
    </div>
  );
}
