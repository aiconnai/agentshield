#!/bin/sh
# AgentShield VS Code Extension Publisher
# Usage:
#   VSCE_PAT="<token>" OVSX_PAT="<token>" ./publish.sh

set -e

DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$DIR"

echo "📦 Packaging AgentShield VS Code extension..."
npm run compile
npm test
npx vsce package --out agentshield-1.0.0.vsix

echo "✅ Package created: agentshield-1.0.0.vsix"

# Publish to Visual Studio Marketplace
if [ -n "$VSCE_PAT" ]; then
  echo "🚀 Publishing to Visual Studio Marketplace..."
  npx vsce publish -p "$VSCE_PAT"
  echo "✅ Published to Visual Studio Marketplace: https://marketplace.visualstudio.com/items?itemName=aiconnai-vs.agentshield"
else
  echo "ℹ️  VSCE_PAT not provided. Skipping Visual Studio Marketplace publish."
  echo "   To publish, set: export VSCE_PAT='<Azure DevOps PAT>'"
fi

# Publish to Open VSX Registry (Cursor, Windsurf, VSCodium)
if [ -n "$OVSX_PAT" ]; then
  echo "🚀 Publishing to Open VSX Registry..."
  npx -y ovsx publish agentshield-1.0.0.vsix -p "$OVSX_PAT"
  echo "✅ Published to Open VSX Registry: https://open-vsx.org/extension/aiconnai/agentshield"
else
  echo "ℹ️  OVSX_PAT not provided. Skipping Open VSX publish."
  echo "   To publish, set: export OVSX_PAT='<Open VSX Token>'"
fi

echo "\n🎉 Done!"
