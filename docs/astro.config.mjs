import { defineConfig } from "astro/config";
import zueDocs from "zuedocs/astro";

export default defineConfig({
  output: "static",
  site: "https://angelos.ashray.xyz",
  integrations: [zueDocs()],
  vite: {
    build: {
      // ZueDocs lazy-loads Mermaid only for diagram pages. Mermaid's generated
      // parser is a single large module, so keep the shared template threshold.
      chunkSizeWarningLimit: 700
    }
  }
});
