# App

- **Source:** `src/App.tsx`
- **Description:** No module header comment.

Plain-reference document for `src/App.tsx`. Summarised from source; the file itself is authoritative.

## Dependencies

```
./App.css
```

## Top-level symbols

```
ThemeContext
BrandContext
useTheme
ctx
useBrand
getPageFromHash
raw
getHashParam
Logo
svg
toggleTheme
next
brandValue
themeValue
base
suffix
cur
onHashChange
goHome
```

## Exports

```
export const ThemeContext = createContext<ThemeContextValue | null>(null);
export interface BrandContextValue {
export const BrandContext = createContext<BrandContextValue | null>(null);
export function useTheme(): ThemeContextValue {
export function useBrand(): BrandContextValue {
export { Logo };
export default function App() {
```
