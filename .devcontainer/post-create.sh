#!/bin/bash
# SPDX-FileCopyrightText: GitHub, Inc.
# SPDX-License-Identifier: MIT

set -e

echo "🚀 Setting up seclab-taskflows-fuzzing development environment..."

# Create Python virtual environment
echo "📦 Creating Python virtual environment..."
python3 -m venv .venv

# Activate virtual environment and install dependencies
echo "📥 Installing Python dependencies..."
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install hatch
hatch build

# Install this package from local directory, with the benchmark extra
# (matplotlib) that scripts/fuzzing/run_benchmark.py --record needs.
pip install -e '.[benchmark]'

echo "✅ Development environment setup complete!"
