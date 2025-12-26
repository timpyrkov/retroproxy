import pathlib
import sys


# Allow `pytest` to import `scripts.retroproxy` when running from the repo root
# without installing as a package.
REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))


from scripts.retroproxy import RetroConverter


def _read_fixture(name: str) -> str:
    p = pathlib.Path(__file__).resolve().parent / name
    return p.read_text(encoding="utf-8", errors="replace")


def test_convert_google_fixture_smoke() -> None:
    html = _read_fixture("Google.html")
    out = RetroConverter(keep_images=False).convert_to_string(html, base_url="https://www.google.com/")
    assert "<!DOCTYPE HTML PUBLIC" in out
    assert "<title>Google</title>" in out
    assert "<script" not in out.lower()


def test_convert_dosbox_fixture_preserves_links() -> None:
    html = _read_fixture("Dosbox.html")
    out = RetroConverter(keep_images=False).convert_to_string(html, base_url="https://www.dosbox.com/")
    assert "<a" in out.lower()
    assert "href=" in out.lower()
    assert "<script" not in out.lower()


def test_convert_barcelona_fixture_smoke() -> None:
    html = _read_fixture("Barcelona.html")
    out = RetroConverter(keep_images=False).convert_to_string(html, base_url="https://en.wikipedia.org/wiki/Barcelona")
    assert "<!DOCTYPE HTML PUBLIC" in out
    assert "Barcelona" in out
    assert "<script" not in out.lower()


if __name__ == "__main__":
    # Manual run helper: generate outputs next to the fixtures.
    tests_dir = pathlib.Path(__file__).resolve().parent
    conv = RetroConverter(keep_images=False)

    for inp, base in [
        ("Google.html", "https://www.google.com/"),
        ("Dosbox.html", "https://www.dosbox.com/"),
        ("Barcelona.html", "https://en.wikipedia.org/wiki/Barcelona"),
    ]:
        src = _read_fixture(inp)
        out = conv.convert_to_string(src, base_url=base)
        out_path = tests_dir / (pathlib.Path(inp).stem + ".converted.html")
        out_path.write_text(out, encoding="utf-8")
        print(f"Wrote {out_path}")
