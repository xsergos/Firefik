const flag = (import.meta.env.VITE_PANEL_MODE ?? "").toString().toLowerCase();

export const isPanelMode = flag === "fleet" || flag === "1" || flag === "true";
