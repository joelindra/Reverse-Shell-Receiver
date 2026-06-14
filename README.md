# Reverse Shell Receiver

A Burp Suite extension for penetration testers that combines an **HTTP webhook listener (OAST)**, an **interactive reverse shell terminal**, and a **multi-platform payload generator** — all within a single integrated tab.

---

## Features

### HTTP Webhook Listener (OAST)
- Starts a TCP socket server on any specified port to capture raw inbound HTTP requests
- Records each request with index, HTTP method, full URL, and timestamp in a sortable, filterable history table
- Clicking any row opens the **full request and response** side-by-side in native Burp `IMessageEditor` panels — complete with syntax highlighting, search, and automatic light/dark theme support
- **"Send to Reverse Shell Receiver"** context menu item available in Proxy History, Message Editor (request/response), and Message Viewer — filtered to valid HTTP contexts only

### Interactive Reverse Shell Terminal
- Receives an incoming reverse shell connection and presents a styled terminal inside Burp
- **Dynamic path tracker**: automatically detects and displays the current working directory on the remote host in real time (e.g., `[Remote] [/var/www/html]`)
- Kali-style prompt (`┌──(Reverse Shell Session)-[Remote][path]` / `└─#`) in a dark-background `JTextPane`
- Separate styled text classes for output, command input, status messages, and path display
- Input field with Enter-to-send; graceful `exit` / `quit` command handling closes the connection cleanly

### Payload Generator
Three payload categories, each with platform and template selection:

| Category | OS | Templates |
|---|---|---|
| Reverse/Bind Shell | Linux/macOS | Bash TCP, Bash UDP, Python3, Perl, PHP, Ruby, Netcat (with -e), Netcat (mkfifo) |
| Reverse/Bind Shell | Windows | PowerShell #1, PowerShell #2 (TLS), Netcat |
| Web Shell | — | PHP Simple Command Shell, PHP Full-featured Shell |
| Data Exfiltration | Linux/macOS + Windows | curl / Invoke-WebRequest one-liners |

- **IP auto-detection**: dropdown populated with all active non-loopback network interfaces (including VPNs)
- **Encoding**: None, Base64 (wraps shell payloads in `echo <b64> | base64 -d | bash`), URL
- Payload output rendered in a native Burp `ITextEditor` (search bar, theme-aware)
- One-click copy to clipboard

### Listener Status Card
- **ONLINE / OFFLINE** badge (colored pill) with "Listener Status" label
- **Listening Addresses** panel: shows each detected IP:port as a clickable chip — click copies to clipboard with a brief toast notification (`Copied: ip:port`)
- VPN hint label shown when non-loopback interfaces are detected

### Port Management
- **Kill Used Ports** button scans for processes occupying the configured port using `netstat` + batch process mapping
- Displays results in a dialog with per-process kill controls
- Works on both Windows (`netstat -ano`, `taskkill`) and Linux (`netstat -tlnp`, `kill`)

### Context Menu Integration
Registered as `IContextMenuFactory`; the "Send to Reverse Shell Receiver" item appears only in:
- Proxy History
- Message Editor (request and response)
- Message Viewer (request and response)
- Target Site Map table

Filtered from all other contexts (scanner, intruder, etc.) to prevent null-reference errors.

### Settings Persistence
Port, mode selection, and other preferences are saved and restored via Burp's built-in preference store across sessions.

---

## Technical Notes

- All socket I/O runs on a managed `ExecutorService` — never on the Swing EDT — so Burp's UI remains responsive during listener start/stop and command dispatch
- Cross-thread fields (`serverSocket`, `clientSocket`, `shellOut`, `currentRemotePath`, etc.) are declared `volatile` for correct visibility between the I/O threads and the EDT
- Extension unload calls `ioExecutor.shutdownNow()` before closing sockets to ensure no orphaned threads remain
- Uses native Burp APIs: `IMessageEditor` (request/response viewer), `ITextEditor` (payload display), `IExtensionHelpers`, `IContextMenuFactory`, `IExtensionStateListener`

---

## Build

**Requirements**
- Java 8 or higher (compiled with `source/target 1.8`)
- Apache Maven 3.x

**Steps**
```bash
git clone https://github.com/your-repo/reverse-shell-receiver.git
cd reverse-shell-receiver/dev
mvn clean package
```

Output artifact:
```
target/reverse-shell-receiver-1.0.0-jar-with-dependencies.jar
```

> On Windows without Maven in PATH, build via WSL:
> ```bash
> wsl -d kali-linux -- bash -c "cd '/mnt/e/path/to/dev' && mvn clean package"
> ```

---

## Installation

1. Open Burp Suite and go to **Extensions** tab (formerly Extender)
2. Click **Add** and set extension type to **Java**
3. Browse to `target/reverse-shell-receiver-1.0.0-jar-with-dependencies.jar`
4. Click **Next** — the **Reverse Shell Receiver** tab will appear in the top navigation

---

## Usage

### HTTP Webhook
1. Select **HTTP Webhook** from the mode dropdown
2. Enter a port number and click **Start Listener**
3. Trigger an out-of-band HTTP request from your target (e.g., via SSRF or injected `fetch()`)
4. The request appears in the history table — click the row to inspect full request and response

### Reverse Shell
1. Select **Reverse Shell** mode and click **Start Listener**
2. Open the **Payload Generator** tab, select the target OS and shell type, copy the generated payload
3. Execute the payload on the target machine
4. The terminal session opens automatically; type commands and press Enter to execute

### Send from Burp Context Menu
Right-click any request in Proxy History or Message Editor and select **Send to Reverse Shell Receiver** to add it directly to the webhook history table.

---

## Requirements

- Burp Suite Professional or Community Edition (latest version recommended)
- Network access to the port configured for listening

---

## Author

**Joel Indra**
