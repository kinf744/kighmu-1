#!/bin/bash
# install.sh — KIGHMU AI installer
set -e

echo "📦 Installation KIGHMU AI..."

# Vérifier Node.js >= 18
NODE_VER=$(node -e "process.exit(parseInt(process.version.slice(1)) < 18 ? 1 : 0)" 2>/dev/null && echo ok || echo fail)
if [ "$NODE_VER" = "fail" ]; then
  echo "⚠ Node.js 18+ requis. Installation..."
  curl -fsSL https://deb.nodesource.com/setup_20.x | bash -
  apt-get install -y nodejs
fi

# Installer depuis GitHub
git clone https://github.com/kinf744/kighmu-1.git ~/.kighmu 2>/dev/null || \
  git -C ~/.kighmu pull

cd ~/.kighmu
npm install --silent
npm install -g . --silent

echo "✅ KIGHMU AI installé ! Lance : kighmu-ai"
