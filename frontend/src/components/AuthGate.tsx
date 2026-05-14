import { useEffect, useState } from "react";
import { useLocation, useNavigate, Outlet } from "react-router-dom";
import { whoami } from "@/lib/fleetApi";

type Status = "checking" | "authed" | "unauthed";

export function AuthGate() {
  const [status, setStatus] = useState<Status>("checking");
  const navigate = useNavigate();
  const location = useLocation();

  useEffect(() => {
    let cancelled = false;
    whoami()
      .then((w) => {
        if (cancelled) return;
        if (w === null) {
          setStatus("unauthed");
          return;
        }
        setStatus("authed");
      })
      .catch(() => {
        if (!cancelled) setStatus("unauthed");
      });
    return () => {
      cancelled = true;
    };
  }, [location.pathname]);

  useEffect(() => {
    if (status === "unauthed" && location.pathname !== "/login") {
      navigate("/login", { replace: true });
    }
  }, [status, location.pathname, navigate]);

  if (status === "checking") {
    return (
      <div className="min-h-screen flex items-center justify-center text-sm text-muted-foreground">
        Checking session…
      </div>
    );
  }
  if (status === "unauthed") {
    return null;
  }
  return <Outlet />;
}
