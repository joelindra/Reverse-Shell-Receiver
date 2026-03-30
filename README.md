# Reverse Shell Receiver v1.0.0

**Reverse Shell Receiver** is a multi-functional Burp Suite extension designed for modern security testing. It combines an **Adaptive HTTP Webhook (OAST)** listener for out-of-band data exfiltration with a high-performance **Interactive Reverse Shell Terminal**.

Built for stability, speed, and a premium "hacker-style" aesthetic, this tool is an essential addition to any penetration tester's toolkit.

---

## 🎯 Key Features

### 1. Adaptive HTTP Webhook (OAST)
*   **Reliable Data Capture**: Rebuilt to parse `Content-Length` headers, ensuring complete request body capture even on slow or unstable network connections.
*   **Syntax Highlighting**: Built-in native Burp message editor for viewing intercepted webhooks with full syntax highlighting.
*   **Resizable History**: Easily manage and sort thousands of intercepted requests in a high-performance interactive table.

### 2. Interactive Reverse Shell Terminal
*   **Modern Hacker Esthetics**: A dedicated shell terminal with a **Deep Dark Background** (`#0C0C0C`) and high-contrast **Vibrant Red** output.
*   **Dynamic Remote Path Tracker**: Automatically tracks and displays your current working directory on the target server in real-time (e.g., `[Remote] [/etc/passwd]`).
*   **Kali Linux Style Prompt**: Professional neon-cyan prompt headers (`┌──└─`) for an authentic terminal experience.
*   **Persistent Sessions**: Handles multiple command executions within the same shell session seamlessly.

### 3. Smart Payload Generator
*   **Multi-Platform Templates**: Instant access to shell payloads for Bash, Python, Perl, PHP, PowerShell, and more.
*   **One-Click Encoding**: Built-in support for Base64 and URL encoding to bypass WAFs and simple input filters.
*   **Auto-IP Detection**: Detects all active local network interfaces (including VPNs) for quick listener configuration.

### 4. System Optimizations
*   **Instant Port Management**: A "Kill Used Ports" feature optimized with **Batch Process Mapping**, allowing you to clear blocked ports on Windows and Linux instantly.
*   **Windows Shell Stability**: Fully compatible with Windows shell environments by correctly handling pipes (`|`) via `ProcessBuilder`.

---

## 🛠️ Build & Installation

### Prerequisites
*   **Java Development Kit (JDK)** 11 or higher
*   **Apache Maven** installed and configured in your environment

### Building the Extension
1.  **Clone the Repository**:
    ```bash
    git clone https://github.com/your-repo/reverse-shell-receiver.git
    cd reverse-shell-receiver
    ```
2.  **Compile & Package**:
    Run the following command to download dependencies and build the `.jar` file:
    ```bash
    mvn clean package
    ```
3.  **Locate Artifact**:
    The compiled extension will be located in the `target/` directory:
    `target/ReverseShellReceiver-1.0.0.jar`

### Loading into Burp Suite
1. Opening Burp Suite, go to the **Extensions** (formerly Extender) tab.
2. Click **Add** -> Select **Java** as the extension type.
3. Browse and select the `.jar` file from your `target/` folder.
4. The **Reverse Shell Receiver** tab will appear in your top navigation menu.

---

## 🚀 Usage Guide

### Mode: HTTP Webhook
1.  Select **HTTP Webhook** from the mode menu.
2.  Check your local IP from the generator dropdown and set your desired **Port**.
3.  Click **Start Listener**.
4.  Send any HTTP request to `http://YOUR_IP:PORT/` to see it appear in the history table.

### Mode: Reverse Shell
1.  Select **Reverse Shell** mode and click **Start Listener**.
2.  Use the **Payload Generator** to create a payload matching your target's OS.
3.  Execute the payload on the target.
4.  The terminal will automatically clear and greet you with a session banner. You are now interactive!

---

## 🛡️ Requirements
*   **Burp Suite Professional or Community** (Latest version recommended)
*   Network access to the specified listening ports.

---

## 👨‍💻 Author
**Joel Indra**
