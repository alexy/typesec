#!/usr/bin/env bash
# Build the typesec-wasm npm package into ./pkg.
#
# Requires the wasm target and a matching wasm-bindgen CLI:
#   rustup target add wasm32-unknown-unknown
#   cargo install wasm-bindgen-cli --version <the wasm-bindgen version in Cargo.lock>
# (or use `wasm-pack build --target nodejs crates/typesec-wasm`, which bundles both).
#
# Usage: ./build-npm.sh [nodejs|web|bundler]   (default: nodejs)
set -euo pipefail

TARGET="${1:-nodejs}"
CRATE_DIR="$(cd "$(dirname "$0")" && pwd)"
WORKSPACE_ROOT="$(cd "$CRATE_DIR/../.." && pwd)"
OUT="$CRATE_DIR/pkg"
VERSION="$(grep -m1 '^version' "$WORKSPACE_ROOT/Cargo.toml" | sed 's/.*"\(.*\)".*/\1/')"

echo "› building typesec-wasm (release, wasm32) …"
cargo build -p typesec-wasm --target wasm32-unknown-unknown --release \
  --manifest-path "$WORKSPACE_ROOT/Cargo.toml"

WASM="$WORKSPACE_ROOT/target/wasm32-unknown-unknown/release/typesec_wasm.wasm"

echo "› generating $TARGET bindings via wasm-bindgen …"
rm -rf "$OUT"
mkdir -p "$OUT"
wasm-bindgen "$WASM" --out-dir "$OUT" --target "$TARGET" --out-name typesec_wasm

# wasm-bindgen doesn't emit a package.json (wasm-pack does); write one that
# points at the generated entry files for the chosen target.
MAIN="typesec_wasm.js"
cat > "$OUT/package.json" <<JSON
{
  "name": "typesec-wasm",
  "version": "$VERSION",
  "description": "Type-level security for AI agents: policy-gated tool calls for JS/TS (OpenAI, Anthropic, LangChain, Pydantic AI, MCP)",
  "license": "MIT OR Apache-2.0",
  "repository": { "type": "git", "url": "https://github.com/querygraph/typesec" },
  "keywords": ["security", "agents", "llm", "tool-calls", "rbac", "wasm"],
  "type": "$([ "$TARGET" = nodejs ] && echo commonjs || echo module)",
  "main": "$MAIN",
  "types": "typesec_wasm.d.ts",
  "files": ["typesec_wasm.js", "typesec_wasm.d.ts", "typesec_wasm_bg.wasm", "typesec_wasm_bg.wasm.d.ts", "README.md"],
  "sideEffects": ["./typesec_wasm.js"]
}
JSON

cp "$CRATE_DIR/README.md" "$OUT/README.md"

echo "› built $TARGET package in $OUT"
if [ "$TARGET" = nodejs ]; then
  echo "› smoke-testing with node …"
  node "$CRATE_DIR/smoke.mjs"
fi
echo "✓ done — publish with: (cd $OUT && npm publish)"
