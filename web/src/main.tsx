import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { BrowserRouter } from "react-router";
import "@fontsource/jetbrains-mono/latin-400.css";
import "@fontsource/jetbrains-mono/latin-700.css";
import "@fontsource/jetbrains-mono/latin-ext-400.css";
import "@fontsource/jetbrains-mono/latin-ext-700.css";
import App from "./App";
import "./index.css";

// Upper bound on how long a slow or blocked font download may hold back
// the first paint; after it the app renders with the fallback font.
const FONT_TIMEOUT_MS = 3000;

// Render only once the UI font is ready, so the first paint already uses
// JetBrains Mono instead of flashing the fallback font and reflowing.
function fontsReady(): Promise<unknown> {
  if (!("fonts" in document)) return Promise.resolve();
  const loads = Promise.all([
    document.fonts.load('400 1em "JetBrains Mono"'),
    document.fonts.load('700 1em "JetBrains Mono"'),
  ]).catch(() => undefined);
  const timeout = new Promise((resolve) => setTimeout(resolve, FONT_TIMEOUT_MS));
  return Promise.race([loads, timeout]);
}

void fontsReady().then(() => {
  createRoot(document.getElementById("root")!).render(
    <StrictMode>
      <BrowserRouter>
        <App />
      </BrowserRouter>
    </StrictMode>,
  );
});
