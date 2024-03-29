import { defineConfig } from "tsup";

export default defineConfig({
  entryPoints: ["./lib/index.ts"],
  format: ["cjs", "esm"],
  dts: true,
  shims: true,
  skipNodeModulesBundle: true,
  clean: true,
});
