import i18n from "i18next";
import LanguageDetector from "i18next-browser-languagedetector";
import { initReactI18next } from "react-i18next";

import en from "./locales/en.json";

export const resources = {
  en: { translation: en },
} as const;

export type AppLocale = keyof typeof resources;

export function initI18n(): typeof i18n {
  if (i18n.isInitialized) return i18n;
  i18n
    .use(LanguageDetector)
    .use(initReactI18next)
    .init({
      resources,
      fallbackLng: "en",
      supportedLngs: ["en"],
      interpolation: { escapeValue: false },
      detection: {
        order: ["localStorage", "navigator"],
        lookupLocalStorage: "firefik.lang",
        caches: ["localStorage"],
      },
    });
  return i18n;
}

export default i18n;
