import { defineConfig, globalIgnores } from "eslint/config";
import nextVitals from "eslint-config-next/core-web-vitals";
import nextTs from "eslint-config-next/typescript";

const eslintConfig = defineConfig([
  ...nextVitals,
  ...nextTs,
  // Override default ignores of eslint-config-next.
  globalIgnores([
    // Default ignores of eslint-config-next:
    ".next/**",
    "out/**",
    "build/**",
    "next-env.d.ts",
    // The Python side of this project. Without these, eslint descends into
    // .venv (site-packages) and reports warnings against third-party
    // JavaScript shipped inside sklearn, which are not ours to fix.
    ".venv/**",
    "**/__pycache__/**",
    ".pytest_cache/**",
    // Source trees of the analysis engine, scanner and API.
    "ai/**",
    "scanner/**",
    "backend/**",
  ]),
]);

export default eslintConfig;
