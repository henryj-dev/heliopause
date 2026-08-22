import { pickLang, type Lang } from "../i18n.ts";

export type ThemePref = "system" | "light" | "dark";
export type LangPref = Lang;

const THEME_KEY = "heliopause-theme";
const LANG_KEY = "heliopause-lang";

function readTheme(): ThemePref {
  if (typeof localStorage === "undefined") return "system";
  const value = localStorage.getItem(THEME_KEY);
  return value === "light" || value === "dark" ? value : "system";
}

function readLang(): LangPref {
  if (typeof localStorage !== "undefined") {
    const stored = localStorage.getItem(LANG_KEY);
    if (stored === "ko" || stored === "en") return stored;
  }
  if (typeof navigator !== "undefined") {
    return pickLang({ acceptLanguage: navigator.language });
  }
  return "en";
}

function paint(theme: ThemePref, lang: LangPref): void {
  if (typeof document === "undefined") return;
  if (theme === "system") document.documentElement.removeAttribute("data-theme");
  else document.documentElement.setAttribute("data-theme", theme);
  document.documentElement.lang = lang;
}

export interface ChromePrefs {
  readonly theme: ThemePref;
  readonly lang: LangPref;
  setTheme(next: ThemePref): void;
  cycleTheme(): void;
  setLang(next: LangPref): void;
}

let instance: ChromePrefs | undefined;

function createPrefs(): ChromePrefs {
  const initialTheme = readTheme();
  const initialLang = readLang();
  let theme = $state<ThemePref>(initialTheme);
  let lang = $state<LangPref>(initialLang);
  paint(initialTheme, initialLang);

  return {
    get theme() {
      return theme;
    },
    get lang() {
      return lang;
    },
    setTheme(next: ThemePref) {
      theme = next;
      localStorage.setItem(THEME_KEY, next);
      paint(theme, lang);
    },
    cycleTheme() {
      const order: ThemePref[] = ["system", "light", "dark"];
      const next = order[(order.indexOf(theme) + 1) % order.length]!;
      theme = next;
      localStorage.setItem(THEME_KEY, next);
      paint(theme, lang);
    },
    setLang(next: LangPref) {
      lang = next;
      localStorage.setItem(LANG_KEY, next);
      paint(theme, lang);
    },
  };
}

/** One prefs object for the chrome and every screen. A second `$state` would not see setLang. */
export function chromePrefs(): ChromePrefs {
  instance ??= createPrefs();
  return instance;
}
