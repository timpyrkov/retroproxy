#!/usr/bin/env python3

import argparse
import re
import socket
import sys
import urllib.parse
import urllib.request
from html import escape
from html.parser import HTMLParser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Dict, List, Optional, Set, Tuple


class RetroParser(HTMLParser):
    """HTML sanitizer/parser that reduces modern HTML to a retro-friendly subset.

    The parser keeps common HTML 3.2-era structural tags (headings, lists, simple
    tables, basic inline formatting) and preserves hyperlinks.

    It drops or ignores modern/unsafe constructs such as scripts, styles, SVG,
    iframes, and other embedded content. If the input document contains a
    `<body>`, only that body's contents are emitted (the output wrapper document
    is produced by `RetroConverter`).
    """

    def __init__(self, base_url: Optional[str], keep_images: bool):
        """Create a parser.

        Args:
            base_url: Base URL for resolving relative `href`/`src` values.
            keep_images: If True, keep `<img>` tags (sanitized). If False, drop them.
        """
        super().__init__(convert_charrefs=True)
        self.base_url = base_url
        self.keep_images = keep_images

        self._out: List[str] = []
        self._tag_stack: List[str] = []

        self._in_head = False
        self._in_body = False
        self._saw_body = False

        self._drop_content_tags: Set[str] = {
            "script",
            "style",
            "svg",
            "canvas",
            "noscript",
            "iframe",
            "object",
            "embed",
            "video",
            "audio",
            "source",
            "picture",
            "map",
            "area",
        }
        self._dropping_stack: List[str] = []

        self._allowed_tags: Set[str] = {
            "p",
            "br",
            "hr",
            "a",
            "img",
            "b",
            "i",
            "u",
            "em",
            "strong",
            "pre",
            "code",
            "blockquote",
            "ul",
            "ol",
            "li",
            "dl",
            "dt",
            "dd",
            "h1",
            "h2",
            "h3",
            "h4",
            "h5",
            "h6",
            "table",
            "tr",
            "td",
            "th",
            "center",
            "div",
            "span",
        }

        self._rewrite_to_p: Set[str] = {"section", "article", "nav", "header", "footer", "main", "aside"}
        self._void_tags: Set[str] = {"br", "hr", "img", "meta"}

    def get_html(self) -> str:
        """Return the accumulated sanitized HTML fragment."""
        return "".join(self._out)

    def handle_starttag(self, tag: str, attrs: List[Tuple[str, Optional[str]]]) -> None:
        """Handle an opening tag from the source HTML."""
        tag = tag.lower()

        if tag == "head":
            self._in_head = True
            return

        if tag == "body":
            self._in_body = True
            self._saw_body = True
            return

        if self._in_head and tag != "head":
            return

        if self._saw_body and not self._in_body:
            return

        if self._dropping_stack:
            if tag in self._drop_content_tags:
                self._dropping_stack.append(tag)
            return

        if tag in self._drop_content_tags:
            self._dropping_stack.append(tag)
            return

        if tag in self._rewrite_to_p:
            tag = "p"

        if tag == "img" and not self.keep_images:
            return

        if tag not in self._allowed_tags:
            return

        if self._saw_body and not self._in_body:
            return

        attr_str = self._filter_attrs(tag, attrs)
        self._out.append(f"<{tag}{attr_str}>")
        if tag not in self._void_tags:
            self._tag_stack.append(tag)

    def handle_endtag(self, tag: str) -> None:
        """Handle a closing tag from the source HTML."""
        tag = tag.lower()

        if tag == "head":
            self._in_head = False
            return

        if tag == "body":
            self._in_body = False
            return

        if self._in_head:
            return

        if self._saw_body and not self._in_body:
            return

        if self._dropping_stack:
            if tag == self._dropping_stack[-1]:
                self._dropping_stack.pop()
            return

        if tag in self._rewrite_to_p:
            tag = "p"

        if tag == "img":
            return

        if tag not in self._allowed_tags:
            return

        if tag in self._tag_stack:
            while self._tag_stack:
                open_tag = self._tag_stack.pop()
                self._out.append(f"</{open_tag}>")
                if open_tag == tag:
                    break

    def handle_startendtag(self, tag: str, attrs: List[Tuple[str, Optional[str]]]) -> None:
        """Handle a self-closing tag (e.g. `<br/>`) from the source HTML."""
        self.handle_starttag(tag, attrs)
        tag = tag.lower()
        if tag in self._allowed_tags and tag in self._void_tags:
            return

    def handle_data(self, data: str) -> None:
        """Handle raw text nodes."""
        if self._dropping_stack or self._in_head:
            return
        if not data:
            return

        if self._saw_body and not self._in_body:
            return
        self._out.append(escape(data, quote=False))

    def handle_entityref(self, name: str) -> None:
        """Handle named entity references like `&nbsp;`."""
        if self._dropping_stack or self._in_head:
            return
        if self._saw_body and not self._in_body:
            return
        self._out.append(f"&{name};")

    def handle_charref(self, name: str) -> None:
        """Handle numeric character references like `&#160;` or `&#xA0;`."""
        if self._dropping_stack or self._in_head:
            return
        if self._saw_body and not self._in_body:
            return
        self._out.append(f"&#{name};")

    def handle_comment(self, data: str) -> None:
        """Handle comments (dropped)."""
        return

    def close(self) -> None:
        """Finalize parsing and close any still-open tags."""
        super().close()
        while self._tag_stack:
            self._out.append(f"</{self._tag_stack.pop()}>\n")

    def _filter_attrs(self, tag: str, attrs: List[Tuple[str, Optional[str]]]) -> str:
        """Return a sanitized attribute string for an allowed tag.

        Only a small set of attributes is kept:
        - `a`: href/name/title
        - `img`: src/alt/width/height (only when images are kept)
        - basic align/valign on a few block/table tags
        """
        out: Dict[str, str] = {}
        attrs_dict = {k.lower(): (v if v is not None else "") for k, v in attrs}

        if tag == "a":
            href = attrs_dict.get("href", "").strip()
            if href:
                href = self._absolutize_url(href)
                if href and not href.lower().startswith("javascript:"):
                    out["href"] = href
            name = attrs_dict.get("name", "").strip()
            if name:
                out["name"] = name
            title = attrs_dict.get("title", "").strip()
            if title:
                out["title"] = title

        elif tag == "img":
            src = attrs_dict.get("src", "").strip()
            if src:
                src = self._absolutize_url(src)
                if src and not src.lower().startswith("javascript:"):
                    out["src"] = src
            alt = attrs_dict.get("alt", "").strip()
            if alt:
                out["alt"] = alt
            for k in ("width", "height"):
                v = attrs_dict.get(k, "").strip()
                if v and re.fullmatch(r"\d+", v):
                    out[k] = v

        elif tag in {"table", "td", "th", "tr", "p", "div", "center", "h1", "h2", "h3", "h4", "h5", "h6"}:
            align = attrs_dict.get("align", "").strip().lower()
            if align in {"left", "center", "right"}:
                out["align"] = align
            valign = attrs_dict.get("valign", "").strip().lower()
            if valign in {"top", "middle", "bottom"}:
                out["valign"] = valign

        if not out:
            return ""

        parts = []
        for k, v in out.items():
            parts.append(f' {k}="{escape(v, quote=True)}"')
        return "".join(parts)

    def _absolutize_url(self, url: str) -> str:
        """Resolve a possibly-relative URL against `base_url` (if provided)."""
        if not self.base_url:
            return url
        try:
            return urllib.parse.urljoin(self.base_url, url)
        except Exception:
            return url


class RetroConverter:
    """Convert modern HTML into a simplified, retro-compatible HTML document.

    Converter is aimed at old browsers (e.g. IE3-era) and text-mode browsers. It:
    - extracts `<title>`
    - sanitizes the body using `RetroParser`
    - iteratively removes empty tags with a max-iteration cutoff
    - emits a minimal HTML 3.2-ish wrapper document
    """

    def __init__(self, keep_images: bool = False, empty_tag_max_iter: int = 25):
        """Create a converter.

        Args:
            keep_images: If True, keep `<img>` tags.
            empty_tag_max_iter: Max passes for removing newly-empty tags.
        """
        self.keep_images = keep_images
        self.empty_tag_max_iter = empty_tag_max_iter

    def convert_to_string(self, html: str, base_url: Optional[str] = None) -> str:
        """Convert HTML text to a simplified HTML document string.

        Args:
            html: Source HTML.
            base_url: Base URL used to resolve relative links.
        """
        title = self._extract_title(html)

        parser = RetroParser(base_url=base_url, keep_images=self.keep_images)
        parser.feed(html)
        parser.close()

        body = parser.get_html()
        body = self._remove_empty_tags(body, max_iter=self.empty_tag_max_iter)

        out = []
        out.append('<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2//EN">\n')
        out.append("<html>\n<head>\n")
        out.append(f"<title>{escape(title, quote=False)}</title>\n")
        out.append("</head>\n<body>\n")
        out.append(body)
        out.append("\n</body>\n</html>\n")
        return "".join(out)

    def _extract_title(self, html: str) -> str:
        m = re.search(r"<title\b[^>]*>(.*?)</title>", html, flags=re.IGNORECASE | re.DOTALL)
        if not m:
            return "Converted page"
        title = re.sub(r"\s+", " ", m.group(1))
        title = re.sub(r"<[^>]+>", "", title)
        return title.strip() or "Converted page"

    def _remove_empty_tags(self, html: str, max_iter: int) -> str:
        removable = [
            "p",
            "div",
            "span",
            "center",
            "b",
            "i",
            "u",
            "em",
            "strong",
            "pre",
            "code",
            "blockquote",
            "ul",
            "ol",
            "li",
            "dl",
            "dt",
            "dd",
            "table",
            "tr",
            "td",
            "th",
            "h1",
            "h2",
            "h3",
            "h4",
            "h5",
            "h6",
            "a",
        ]
        tag_group = "|".join(removable)

        ws = r"(?:\s|&nbsp;|&#160;)*"
        pattern = re.compile(rf"<(?P<tag>{tag_group})\b[^>]*>{ws}</(?P=tag)>", flags=re.IGNORECASE)

        current = html
        for _ in range(max_iter):
            current, n = pattern.subn("", current)
            if n == 0:
                break
        return current


def _is_html_content_type(content_type: str) -> bool:
    """Return True if a Content-Type header looks like HTML/XHTML."""
    ct = (content_type or "").lower()
    return "text/html" in ct or "application/xhtml" in ct


def _decode_body(raw: bytes, content_type: str) -> str:
    """Decode raw bytes into text using charset from Content-Type when possible."""
    ct = content_type or ""
    m = re.search(r"charset=([^;]+)", ct, flags=re.IGNORECASE)
    if m:
        enc = m.group(1).strip().strip('"').strip("'")
        try:
            return raw.decode(enc, errors="replace")
        except LookupError:
            return raw.decode("utf-8", errors="replace")
    return raw.decode("utf-8", errors="replace")


def _get_lan_ip() -> str:
    """Best-effort detection of the LAN IP address to show to a user.

    This attempts to discover the IP of the interface used for outbound traffic.
    It does not require any inbound port to be open, and it does not need the
    destination to be reachable.
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # Doesn't need to be reachable; used to pick the outbound interface.
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except Exception:
        return socket.gethostbyname(socket.gethostname())
    finally:
        try:
            s.close()
        except Exception:
            pass


def _rewrite_links_to_proxy(html: str, current_url: str) -> str:
    """Rewrite URLs inside HTML to keep navigation inside the proxy.

    Rewrites `href`, `src`, and `action` attribute values to `/fetch?url=...`.
    Relative URLs are normalized to absolute using `current_url` as the base.
    """
    def repl(match: re.Match[str]) -> str:
        attr = match.group("attr")
        quote = match.group("q")
        url = match.group("url")

        if not url:
            return match.group(0)

        lowered = url.lower()
        if lowered.startswith("#"):
            return match.group(0)
        if lowered.startswith("mailto:"):
            return match.group(0)
        if lowered.startswith("javascript:"):
            return match.group(0)

        if lowered.startswith("/fetch?url="):
            return match.group(0)

        abs_url = urllib.parse.urljoin(current_url, url)
        proxied = "/fetch?url=" + urllib.parse.quote(abs_url, safe="")
        return f"{attr}={quote}{proxied}{quote}"

    pattern = re.compile(
        r"(?P<attr>href|src|action)=(?P<q>\"|')(?P<url>[^\"']+)(?P=q)",
        flags=re.IGNORECASE,
    )
    return pattern.sub(repl, html)


def _parse_target_url(handler_path: str) -> Optional[str]:
    """Extract an upstream URL from the incoming request path.

    Supports two request styles:
    - Proxy form: `GET http://example.com/path ...`
    - Gateway form: `GET /fetch?url=http%3A%2F%2Fexample.com%2Fpath ...`
    """
    path = handler_path.strip()

    # When configured as an HTTP proxy, many browsers send an absolute URI here.
    if path.lower().startswith("http://") or path.lower().startswith("https://"):
        return path

    # Our gateway endpoint.
    parsed = urllib.parse.urlsplit(path)
    if parsed.path == "/fetch":
        qs = urllib.parse.parse_qs(parsed.query)
        url = (qs.get("url") or [""])[0]
        url = url.strip()
        if url.lower().startswith("http://") or url.lower().startswith("https://"):
            return url

    return None


class RetroProxyHandler(BaseHTTPRequestHandler):
    """HTTP handler implementing a simple retro-browsing gateway.

    The handler fetches upstream web pages, converts HTML into a simplified
    retro-compatible form, and rewrites links so subsequent navigation remains
    within this proxy.
    """

    protocol_version = "HTTP/1.1"

    def do_CONNECT(self) -> None:
        """Handle HTTPS tunneling requests (not supported).

        Many browsers use CONNECT to tunnel HTTPS through an HTTP proxy.
        We intentionally do not MITM TLS, so CONNECT is rejected with guidance.
        """
        # HTTPS tunneling. IE3 may attempt this for https:// URLs.
        # We intentionally do not MITM here.
        msg = (
            "This proxy does not support CONNECT (HTTPS tunneling).\n"
            "Use http://<proxy>:<port>/fetch?url=https://example.com instead.\n"
        )
        body = msg.encode("utf-8", errors="replace")
        self.send_response(501, "CONNECT not supported")
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        """Serve the index page or fetch+convert an upstream URL."""
        target_url = _parse_target_url(self.path)
        if not target_url:
            self._serve_index()
            return

        try:
            self._fetch_and_respond(target_url)
        except Exception as e:
            body = (f"Upstream fetch failed: {e}\n").encode("utf-8", errors="replace")
            self.send_response(502, "Bad Gateway")
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    def _serve_index(self) -> None:
        """Serve a tiny HTML 3.2 start page with a URL entry form."""
        html = (
            "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 3.2//EN\">\n"
            "<html><head><title>Retro Proxy</title></head><body>\n"
            "<h1>Retro Proxy</h1>\n"
            "<p>Enter a URL to fetch and convert:</p>\n"
            "<form action=\"/fetch\" method=\"get\">\n"
            "<input type=\"text\" name=\"url\" size=\"60\">\n"
            "<input type=\"submit\" value=\"Go\">\n"
            "</form>\n"
            "<p>Examples:</p>\n"
            "<ul>\n"
            "<li><a href=\"/fetch?url=http%3A%2F%2Fexample.com\">http://example.com</a></li>\n"
            "<li><a href=\"/fetch?url=https%3A%2F%2Fexample.com\">https://example.com</a></li>\n"
            "</ul>\n"
            "</body></html>\n"
        )
        body = html.encode("utf-8", errors="replace")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _fetch_and_respond(self, url: str) -> None:
        """Fetch upstream content, convert HTML if needed, and write response."""
        req = urllib.request.Request(
            url,
            headers={
                "User-Agent": "retroproxy/0.1",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Encoding": "identity",
            },
        )

        with urllib.request.urlopen(req, timeout=30) as resp:
            status = getattr(resp, "status", 200)
            reason = getattr(resp, "reason", "OK")
            content_type = resp.headers.get("content-type", "application/octet-stream")
            raw = resp.read()

        if _is_html_content_type(content_type):
            converter = RetroConverter(keep_images=getattr(self.server, "keep_images", False))
            base_url = url
            decoded = _decode_body(raw, content_type)
            out_html = converter.convert_to_string(decoded, base_url=base_url)
            out_html = _rewrite_links_to_proxy(out_html, current_url=base_url)
            body = out_html.encode("utf-8", errors="replace")

            self.send_response(status, reason)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(body)
            return

        # Non-HTML: pass-through.
        self.send_response(status, reason)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(raw)

    def log_message(self, fmt: str, *args) -> None:
        """Log requests to stderr (overrides BaseHTTPRequestHandler logging)."""
        sys.stderr.write("%s - - [%s] %s\n" % (self.address_string(), self.log_date_time_string(), fmt % args))


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Local retro HTML converting proxy/gateway.")
    parser.add_argument("--host", default="0.0.0.0", help="Bind host (default: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=8080, help="Bind port (default: 8080)")
    parser.add_argument("-m", "--images", action="store_true", help="Keep <img> tags in converted HTML")

    args = parser.parse_args(argv)

    httpd = ThreadingHTTPServer((args.host, args.port), RetroProxyHandler)
    httpd.keep_images = bool(args.images)

    bind_host = args.host
    if bind_host == "0.0.0.0":
        try:
            bind_host = _get_lan_ip()
        except Exception:
            bind_host = "<this-host>"

    sys.stderr.write(f"Retro proxy listening on http://{bind_host}:{args.port}/\n")
    sys.stderr.write("Open / in a browser to use the URL form.\n")

    httpd.serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
