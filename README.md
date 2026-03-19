# Reverse Shell Receiver for Burp Suite

A powerful Burp Suite extension that combines a versatile network listener with a comprehensive payload generator, designed to streamline out-of-band testing and interactive reverse shell operations.

Reverse Shell Receiver integrates two essential pentesting tools directly into your Burp Suite workflow: a multi-mode listener that can catch both HTTP webhooks and interactive shells, and a payload generator with a rich library of templates for various platforms.

## Table of Contents

- [Core Features](#core-features)
  - [Modern Listener Tab](#modern-listener-tab)
  - [Payload Generator](#payload-generator)
- [New Features & Improvements](#new-features--improvements)
- [Dependencies](#dependencies)
- [Building from Source](#building-from-source)
  - [Maven (Recommended)](#maven-recommended)
  - [Ant Build](#ant-build)
- [Installation](#installation)
- [Usage](#usage)
  - [Example 1: HTTP Webhook (OAST)](#example-1-http-webhook-oast)
  - [Example 2: Interactive Reverse Shell](#example-2-interactive-reverse-shell)
- [Author](#author)

---

## Core Features

### Modern Listener Tab

The listener is the core of the tool and operates in two distinct, professionally styled modes:

- **HTTP Webhook Mode**: 
  - Acts as a local web server to log incoming HTTP requests.
  - Ideal for Out-of-Band Application Security Testing (OAST) like Blind SSRF or Blind SQLi.
  - **Native Burp Integration**: Uses the professional `IMessageEditor` for request details, providing syntax highlighting and search.
  - **Resizable Layout**: Uses a `JSplitPane` to allow flexible resizing between the history table and request details.

- **Reverse Shell Mode**: 
  - Turns the listener into an interactive handler for reverse shells.
  - **Terminal-Like UI**: Features a clean, dark-themed terminal interface for command execution directly within Burp.
  - **Command History**: Supports local commands like `clear` to manage the terminal output.

- **Port Utility**: Includes a "Kill Used Ports" utility to identify and terminate processes blocking your desired listener ports.

### Payload Generator

A comprehensive generator to create one-liners and scripts tailored for your listener.

- **Rich Template Library**: Includes templates for Bash, PowerShell, Python, Netcat, Perl, PHP, Ruby, and more.
- **Categorized Payloads**: Organized into Reverse/Bind Shell, Web Shell, and Data Exfiltration.
- **Auto-Fill**: One-click "Auto-fill from Listener" to sync your active listener's IP and port with the generator.

---

## New Features & Improvements

- **Resource Cleanup**: Intelligent memory and socket management to prevent resource leaks when the extension is unloaded.
- **Non-Blocking UI**: All network operations and port scanning now run in background threads, ensuring the Burp Suite UI remains responsive.
- **Context Menu Integration**: Right-click any request in Burp (Proxy, Repeater, etc.) and select **"Send to Reverse Shell Receiver"** to log it immediately.
- **Settings Persistence**: Your port and mode preferences are automatically saved and restored between Burp sessions.

---

## Dependencies

- **Java JDK 8 or higher**
- **Burp Extender API** (Version 2.3 or later)

*Note: This extension has been refactored to remove unnecessary third-party dependencies (Jackson, JJWT, etc.), resulting in a lightweight and secure JAR.*

---

## Building from Source

### Maven (Recommended)
The project identifies as a standard Maven project.
```bash
mvn clean package
```
The output JAR will be in the `target/` directory.

### Ant Build
If you prefer Ant or are in a restricted environment:
```bash
ant jar
```
The output JAR will be in the `dist/` directory.

---

## Installation

1. In Burp Suite, go to the **Extensions** tab.
2. Click **Add**.
3. Select **Java** as the extension type.
4. Select the `Reverse_Shell_Receiver.jar` file.
5. Click **Next** and wait for the "Reverse Shell Receiver" tab to appear.

---

## Usage

### Example 1: HTTP Webhook (OAST)
1. In the **Listener** tab, select **HTTP Webhook** mode and click **Start Listener**.
2. Right-click any request in your Burp Proxy and select **"Send to Reverse Shell Receiver"**.
3. View the request immediately in the resizable history table with full syntax highlighting.

### Example 2: Interactive Reverse Shell
1. In the **Listener** tab, select **Reverse Shell** mode and click **Start Listener**.
2. Use the **Payload Generator** to create a payload (e.g., Python Reverse Shell).
3. Execute the payload on the target machine.
4. Return to the Listener tab and interact with the shell through the dedicated terminal interface.

---

## Author

- **Joel Indra**
