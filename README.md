The FazeMCP (Model Context Protocol) is essential for enabling intelligent,
autonomous control of the Faze platform through natural language. It allows users to
integrate powerful AI models like ChatGPT, Claude, or Cursor directly with Faze,
enabling them to launch scans, interpret results, and execute complex attack sequences
using simple prompts. By serving as a communication bridge between AI agents and the
Faze API, the MCP transforms traditional security testing into an automated, agentic process.
This not only reduces manual effort and accelerates testing but also empowers users—technical
and non-technical alike—to leverage cutting-edge AI to interact with and operate the platform
as if they were speaking to a skilled human tester
MCP for the FAZE Agentic Red Team platform and is focused on automated penetration testing and platform management, it should stay centered on those capabilities. A better one-paragraph version is: FazeMCP is the Model Context Protocol server for the FAZE Agentic Red Team platform, designed to let AI agents and external systems securely manage and operate FAZE through standardized tools and machine-readable responses, including retrieving dashboard and system data, monitoring discovery and scan coverage, launching and duplicating automated penetration tests, configuring scan settings such as authentication profiles, API schemas, headers, cookies, proxies, scheduling, and rate limits, and enabling seamless automation of both security testing and day-to-day platform management across web applications, APIs, and external attack surfaces.
---
STEP 1: UV Installation -
For windows, Open CMD as administrator and run
    powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"
    
For Linux & Mac -
    curl -LsSf https://astral.sh/uv/install.sh | sh

OR
    wget -qO- https://astral.sh/uv/install.sh | sh

---
STEP 2: Pip Install mcp -
    pip install mcp[cli]

---
STEP 3: Insert to Claude -
Open PowerShell (on Windows) or your Terminal (on macOS/Linux) and change directory to where your FazeMCP.py file is located.
Enter and execute the command below:

uv run mcp install FazeMCP.py
---
STEP 4: Json Configuration -
Open Claude App
Go to file > Settings > Developers > Edit Config
Edit "claude_desktop_config" file
Windows:
    "FazeMCP": {
          "command": "C:\\Users\\UserName\\.local\\bin\\uv.EXE",
          "args": [
            "run",
            "--with",
            "mcp[cli]",
            "mcp",
            "run",
            "to/your/path/FazeMCP.py"
          ],
          "env": {
            "API_KEY": "xxxxxxxx-xxxx-xxxx-xxxxxxxx",
            "API_GATEWAY": "https://api.faze.security"
          }
        }
      }

Linux:
    "FazeMCP": {
          "command": "uv",
          "args": [
            "run",
            "--with",
            "mcp[cli]",
            "mcp",
            "run",
            "to/your/path/FazeMCP.py"
          ],
          "env": {
            "API_KEY": "xxxxxxxx-xxxx-xxxx-xxxxxxxx",
            "API_GATEWAY": "https://api.faze.security"
          }
        }
      }

---
STEP 5: Restart Claude:
Open Task Manager and locate any running “Claude” processes.
Select the process and click End Task.
Relaunch the Claude application.
---
STEP 6: Enjoy!
