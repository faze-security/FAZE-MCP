The FazeMCP (Model Context Protocol) is essential for enabling intelligent,
autonomous control of the Faze platform through natural language. It allows users to
integrate powerful AI models like ChatGPT, Claude, or Cursor directly with Faze,
enabling them to launch scans, interpret results, and execute complex attack sequences
using simple prompts. By serving as a communication bridge between AI agents and the
Faze API, the MCP transforms traditional security testing into an automated, agentic process.
This not only reduces manual effort and accelerates testing but also empowers users—technical
and non-technical alike—to leverage cutting-edge AI to interact with and operate the platform
as if they were speaking to a skilled human tester.

---

## Prerequisites

### 1. Install `uv`

**Windows** — open PowerShell and run:

```powershell
powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"
```

**Linux & macOS**:

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
```

> After installation, note the full path to the `uv` executable — you will need it for the config below.
> - Windows: usually `C:\Users\<YourUser>\.local\bin\uv.exe`
> - Linux/macOS: usually `uv` is on your `PATH` (run `which uv` to confirm)

### 2. Install the MCP CLI

> **Important:** FazeMCP targets the MCP **v1** API (`FastMCP`). Install the matching major version — do **not** install `mcp` 2.x, it will fail to load.

```bash
pip install "mcp[cli]<2"
```

---

## Setup — Cursor

Cursor reads MCP servers from an `mcp.json` file:

- **Per-project:** `<your-project>/.cursor/mcp.json`
- **Global (all projects):** `~/.cursor/mcp.json` (Windows: `C:\Users\<YourUser>\.cursor\mcp.json`)

Create/edit that file:

**Windows**

```json
{
  "mcpServers": {
    "FazeMCP": {
      "command": "C:\\Users\\<YourUser>\\.local\\bin\\uv.exe",
      "args": [
        "run",
        "--with",
        "mcp[cli]<2",
        "--with",
        "requests",
        "mcp",
        "run",
        "C:\\Users\\<YourUser>\\path\\to\\FazeMCP.py"
      ],
      "env": {
        "API_KEY": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
        "API_GATEWAY": "https://api.faze.security"
      }
    }
  }
}
```

**Linux / macOS**

```json
{
  "mcpServers": {
    "FazeMCP": {
      "command": "uv",
      "args": [
        "run",
        "--with",
        "mcp[cli]<2",
        "--with",
        "requests",
        "mcp",
        "run",
        "/your/path/FazeMCP.py"
      ],
      "env": {
        "API_KEY": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
        "API_GATEWAY": "https://api.faze.security"
      }
    }
  }
}
```

Then open **Cursor Settings → MCP & Integrations**, confirm **FazeMCP** is enabled with a green status, and press **Refresh** if you just edited the file.

---

## Setup — Claude Desktop

1. Open the Claude Desktop app.
2. Go to **File → Settings → Developer → Edit Config**.
3. Edit `claude_desktop_config.json` and add the server block below.

**Windows**

```json
{
  "mcpServers": {
    "FazeMCP": {
      "command": "C:\\Users\\<YourUser>\\.local\\bin\\uv.exe",
      "args": [
        "run",
        "--with",
        "mcp[cli]<2",
        "--with",
        "requests",
        "mcp",
        "run",
        "C:\\Users\\<YourUser>\\path\\to\\FazeMCP.py"
      ],
      "env": {
        "API_KEY": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
        "API_GATEWAY": "https://api.faze.security"
      }
    }
  }
}
```

**Linux / macOS**

```json
{
  "mcpServers": {
    "FazeMCP": {
      "command": "uv",
      "args": [
        "run",
        "--with",
        "mcp[cli]<2",
        "--with",
        "requests",
        "mcp",
        "run",
        "/your/path/FazeMCP.py"
      ],
      "env": {
        "API_KEY": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
        "API_GATEWAY": "https://api.faze.security"
      }
    }
  }
}
```

### Restart Claude

1. Open Task Manager (Windows) / Activity Monitor (macOS) and end any running **Claude** processes.
2. Relaunch the Claude application.

---

## Usage

Once the server shows as connected, just ask in natural language and the agent will call the matching
FAZE tools, for example:

- "List my Agentic Red Team projects"
- "Show the newest vulnerabilities for project 1028"
- "What attack options are available?"
- "Add https://example.com as an asset and start a recon scan"

---

## General Guidance

- Always use absolute paths for both the `uv` executable and `FazeMCP.py` in the config.
- Keep your `API_KEY` private — treat it as a secret and never commit it to source control.
- The MCP server loads its configuration and code when it starts, so refresh the server in Cursor (or fully restart Claude) after changing the config.
- After enabling the server, confirm it shows a connected status before sending prompts.
- Run only one FazeMCP server instance per client to avoid duplicate tool registrations.
