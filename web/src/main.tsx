import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { BrowserRouter } from "react-router";
import App from "./App";
import "./index.css";

// Upper bound on how long a slow or blocked font download may hold back
// the first paint; after it the app renders with the fallback font.
const FONT_TIMEOUT_MS = 3000;

// Render only once the UI font (Fira Code) is ready, so the first paint
// already uses the target monospace metrics instead of flashing and reflowing.
function fontsReady(): Promise<unknown> {
  if (!("fonts" in document)) return Promise.resolve();
  const loads = Promise.all([
    document.fonts.load('500 1em "Fira Code"'),
    document.fonts.load('600 1em "Fira Code"'),
    document.fonts.load('700 1em "Fira Code"'),
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
