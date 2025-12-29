<h1><p align="left">
  <img src="https://github.com/timpyrkov/retroproxy/blob/master/logo.png?raw=true" alt="RetroProxy logo" height="30" style="vertical-align: middle; margin-right: 10px;">
  <span style="font-size:2.5em; vertical-align: middle;"><b>RetroProxy</b></span>
</p></h1>


A small hobby project to convert modern web pages into simplified HTML that can be displayed by retro browsers (e.g. text-mode browsers and very old Windows browsers like Internet Explorer 3).

This repository contains:

- `scripts/retroproxy.py` — the main script. Runs a local “retro gateway” proxy server on a modern machine (Mac/Linux) so a retro PC on the same LAN can browse *through* it.
- `scripts/whatismyip.py` — helper tool to print local interface IPv4 addresses.
- `tests/test_converter.py` — pytest + manual test runner for the HTML converter.

## What this project does (in plain words)

Modern web pages contain a lot of things that old browsers cannot handle:

- JavaScript
- CSS layouts
- modern HTML elements
- SVG / Canvas / video, etc.

This project fetches the page on a modern computer, removes unsupported parts, keeps links, and produces simple HTML closer to the HTML 3.2 era.

## Requirements

- Python 3 (no third-party dependencies)
- A modern machine to run the proxy (MacOS, Ubuntu, Raspberry Pi OS, etc.)
- A retro machine (optional) such as Windows 95/98 with IE3/IE4, or DOS + Lynx, on the same LAN

## Quick start: test the converter

The HTML converter logic lives inside `scripts/retroproxy.py` (classes `RetroParser` and `RetroConverter`).

### Run tests with pytest

```bash
pytest -q
```

### Manual conversion run (writes converted files next to fixtures)

```bash
python3 tests/test_converter.py
```

## Main Goal: browse the web from a retro PC through a modern machine

### Why a proxy/gateway is needed

Old browsers usually cannot handle:

- HTTPS/TLS of modern sites
- modern HTML/CSS/JS

A modern proxy machine can:

1) fetch the real page from the internet (including HTTPS)
2) convert it to simplified HTML
3) serve it to the retro browser over plain HTTP

## Run the retro proxy (modern machine)

On your modern machine (Mac/Linux/Raspberry Pi/etc.), copy `scripts/retroproxy.py` to a location you want to run a local proxy server and run:

```bash
python3 scripts/retroproxy.py --host 0.0.0.0 --port 8080
```

- `--host 0.0.0.0` means “listen on all network interfaces”, so other devices on your LAN can access it.
- The proxy prints a URL like `http://192.168.1.10:8080/`. Use `scripts/whatismyip.py` to check the actual IP address of your modern machine and use it in the URL. That is the address your retro PC should open.

### Check if the port is already in use (macOS)

If the proxy fails to start, another program may already be listening on the same port.

Check if something is using port `8080`:

```bash
lsof -nP -iTCP:8080 -sTCP:LISTEN
```

List all listening TCP servers:

```bash
lsof -nP -iTCP -sTCP:LISTEN
```

Alternative (sometimes useful):

```bash
netstat -anv | grep LISTEN
```

### Or keep images in proxied pages

```bash
python3 scripts/retroproxy.py --host 0.0.0.0 --port 8080 -m
```

## How to use it from the retro PC

### Step 1: find the proxy machine IP

When you start `scripts/retroproxy.py`, it prints something like:

- `Retro proxy listening on http://192.168.1.10:8080/`

In this EXAMPLE:

- Proxy IP is `192.168.1.10`
- Proxy port is `8080`

### Step 2: open the proxy start page in IE

In the retro browser, open:

- `http://192.168.1.10:8080/`

You’ll see a simple page with a text box.

### Step 3: type a URL into the form

Examples:

- `http://example.com`
- `https://en.wikipedia.org/wiki/Barcelona`

The proxy will fetch the page on the modern machine, convert it, and return simplified HTML.

### Full browsing mode (every click stays proxied)

The proxy rewrites links in converted HTML so that:

- clicking links keeps you inside the proxy
- relative URLs are normalized against the current page

So you can usually navigate by clicking as you would normally.

## Optional: configure IE3/IE4 to use the proxy as an HTTP proxy

This is optional because you can already browse via `http://<proxy-ip>:8080/`.

If you want to try setting it as a proxy in IE settings:

- set **HTTP proxy** host to `192.168.1.10` (indicate your actual proxy IP)
- set **port** to `8080` (indicate your actual proxy port)

Notes:

- Modern HTTPS sites usually still won’t work transparently because browsers use `CONNECT` for HTTPS tunneling.
- This proxy intentionally does **not** MITM HTTPS and responds with “CONNECT not supported”.

## Networking checklist (beginner friendly)

If the retro PC cannot connect to the proxy:

- Confirm both machines are on the same LAN and can ping each other.
- Make sure your modern machine firewall allows inbound connections to port `8080`.
- Try opening `http://<proxy-ip>:8080/` from another modern machine first (phone/laptop) to verify it is reachable.
- On the modern machine, keep the `retroproxy.py` running while browsing.

## Troubleshooting

### The proxy start page opens, but some sites show empty content

Some modern sites render the page almost entirely using JavaScript.

This project removes scripts and produces a simplified HTML view, but if the original HTML contains no meaningful server-rendered content, the result can be minimal.

### Images do not show in the retro browser

Possible reasons:

- The page uses HTTPS image URLs and the browser can’t fetch them.
- The images are in a modern format like WebP/AVIF.
- The server blocks hotlinking or requires modern headers.

Try browsing with images disabled (default) or rely on ALT text.

### “CONNECT not supported”

This happens when a browser tries to tunnel HTTPS through the proxy.

Use the gateway style instead:

- `http://<proxy-ip>:8080/fetch?url=https://example.com`

## Security note

This is a hobby project for a trusted home LAN.

- Do not expose this proxy publicly to the internet.
- It fetches arbitrary URLs that a client requests.

### About `--host 0.0.0.0` (important)

Binding to `0.0.0.0` means the proxy listens on **all** network interfaces on your machine.
In practice that usually means:

- It will be reachable from other devices on your LAN (this is what you want for a retro PC).
- It may also be reachable from other networks your machine is connected to (for example: guest Wi‑Fi, VPN, etc.), depending on your routing and firewall settings.

Potential risks:

- Anyone who can reach your machine on that port can ask the proxy to fetch arbitrary URLs.
- This can leak your public IP to websites, fetch unexpected content, or be abused if you accidentally expose it beyond your LAN.

Safer options:

- If you only want to test locally on the same Mac, bind to localhost:
  - `--host 127.0.0.1` (only your machine can access it)
- If you only want to serve your LAN, you can bind to your LAN IP instead of `0.0.0.0`:
  - `--host 192.168.x.y`
- Keep your firewall enabled and allow inbound access only from your local network.

## Files

- `scripts/retroproxy.py` — main proxy/gateway script (also contains converter classes)
- `scripts/whatismyip.py` — helper to print interface IPs
- `tests/test_converter.py` — converter tests (pytest) + manual generator
- `tests/` — HTML fixtures used during development
