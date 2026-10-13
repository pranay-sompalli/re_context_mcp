#!/usr/bin/env bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Auto-setup virtual environment if not already present
if [ ! -f ".venv/bin/python" ]; then
    ./setup.sh >&2
fi

# Execute the MCP server via stdio transport
exec .venv/bin/python context_server.py "$@"
