<h1><p align="left">
  <img src="https://github.com/timpyrkov/retroproxy/blob/master/img/logo.png?raw=true" alt="RetroProxy logo" height="30" style="vertical-align: middle; margin-right: 10px;">
  <span style="font-size:2.5em; vertical-align: middle;"><b>RetroProxy</b></span>
</p></h1>


Convert modern web pages to simplified HTML consumable by retro browsers.

Very old DOS/Windows browsers like DOSLYNX, Internet Explorer 3/4 cannot display most modern web pages.

This project removes unsupported parts (JS, CSS, SVG, canvas, video, etc.), keeps links, and produces simple HTML compatible with HTML 3.2.

### Typical setup (Proxy Server and Retro PC on the same LAN)

```text
         Modern PC                              Retro PC      
       (Mac, Linux)                         (DOS, Win 95/98)    
     ________________                       ________________     
    |  ____________  |                     |  ____________  |    
    | |            | |     URL / Domain    | |            | |    
    | |   Server   | | <------------------ | |   Client   | |    
    | |            | |                     | |            | |    
    | |____________| | ------------------> | |____________| |    
    |________________|   Simplified HTML   |________________|    
       _|________|_                           _|________|_       
     _/ ********** \_                       _/ ********** \_     
    /  ************  \                     /  ************  \    
    ------------------                     ------------------    
                :                               :                
                .................................                
                               LAN                               
```

### Quick start (Windows 95/98)

**On your modern machine** (Mac/Linux/Raspberry Pi/etc.), copy `scripts/retroproxy.py` to a location you want to run a local proxy server and run (defaults to blind host `0.0.0.0`):

```bash
python3 retroproxy.py
```

OR get your server machine IP address:

```bash
python3 whatismyip.py
```

and run with specific host, for example:

```bash
python3 retroproxy.py --host 192.168.1.10
```

The proxy will print a URL like `http://192.168.1.10:8080/`. Use `scripts/whatismyip.py` to check its actual IP address.

**On your retro PC**, open the proxy URL like `http://192.168.1.10:8080/` in the browser. Use the actual IP address of your modern machine instead of `192.168.1.10`.

You will see a start page with a form to enter a URL and start browsing.

![RetroProxy index page](https://github.com/timpyrkov/retroproxy/blob/master/img/index.png?raw=true)


### Quick start (DOS)

Set up a proxy server on a modern machine (Mac, Linux, etc.) and open the proxy URL using the `LYNX.BAT` file.

See details in the `dos/README.md` file.

## What this project does (in plain words)

Modern web pages contain a lot of things that old browsers cannot handle:

- JavaScript
- CSS layouts
- modern HTML elements
- SVG / Canvas / video, etc.

This project fetches the page on a modern computer, removes unsupported parts, keeps links, and produces simple HTML closer to the HTML 3.2 era.

### Full browsing mode (every click stays proxied)

The proxy rewrites links in converted HTML so that:

- clicking links keeps you inside the proxy
- relative URLs are normalized against the current page

So you can usually navigate by clicking as you would normally.

### Why a proxy/gateway is needed

Old browsers usually cannot handle:

- HTTPS/TLS of modern sites
- modern HTML/CSS/JS

A modern proxy machine can:

1) fetch the real page from the internet (including HTTPS)
2) convert it to simplified HTML
3) serve it to the retro browser over plain HTTP

## Requirements

- Python 3 (no third-party dependencies)
- A modern machine to run the proxy (MacOS, Ubuntu, Raspberry Pi OS, etc.)
- A retro machine (optional) such as Windows 95/98 with IE3/IE4, or DOS + Lynx, on the same LAN

## Run the retro proxy (modern machine)

Run:

```bash
python3 scripts/retroproxy.py
```

- Default `--host` is `0.0.0.0` (listen on all network interfaces), so other devices on your LAN can access it.
- When binding to `0.0.0.0`, the proxy tries best-effort LAN IP detection only to print a friendlier URL like `http://192.168.1.10:8080/`.

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

## Run with specific port

```bash
python3 scripts/retroproxy.py --port 8080
```

### Or keep images in proxied pages

```bash
python3 scripts/retroproxy.py --port 8080 -m
```

## Optional: configure IE3/IE4 to use the proxy as an HTTP proxy

This is optional because you can already browse via `http://<proxy-ip>:8080/`.

If you want to try setting it as a proxy in IE settings:

- set **HTTP proxy** host to `192.168.1.10` (indicate your actual proxy IP)
- set **port** to `8080` (indicate your actual proxy port)

Notes:

- Modern HTTPS sites usually still won’t work transparently because browsers use `CONNECT` for HTTPS tunneling.
- This proxy intentionally does **not** MITM HTTPS and responds with “CONNECT not supported”.


## Security note

This is a hobby project for a trusted home LAN.

- Do not expose this proxy publicly to the internet.
- It fetches arbitrary URLs that a client requests.

### About default `--host 0.0.0.0` (important)

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
