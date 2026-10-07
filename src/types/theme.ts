export type ThemeMode = "dark" | "light";

export interface ThemeContextValue {
  theme: ThemeMode;
  toggleTheme: () => void;
}