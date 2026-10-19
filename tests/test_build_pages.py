"""scripts/build_pages.py: the documents as a site for GitHub Pages."""

import importlib.util
import re
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
REPO = "https://github.com/example/project"

_spec = importlib.util.spec_from_file_location("build_pages", ROOT / "scripts" / "build_pages.py")
assert _spec and _spec.loader
build_pages = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(build_pages)


def write(root: Path, files: dict[str, str]) -> list[str]:
    for name, text in files.items():
        (root / name).parent.mkdir(parents=True, exist_ok=True)
        (root / name).write_text(text)
    return [name for name in files if name.endswith(".md")]


def hrefs(html: str) -> list[str]:
    """The links in a page's content, in order."""
    main = re.search(r"<main>(.*?)</main>", html, re.S)
    assert main
    return re.findall(r'href="([^"]*)"', main.group(1))


def test_the_projects_documents_build_with_no_broken_link(tmp_path):
    """Every link between the documents, and to their headings, leads somewhere."""
    sources = subprocess.run(
        ["git", "ls-files", "--", "*.md"], cwd=ROOT, capture_output=True, text=True, check=True
    ).stdout.split()
    written = build_pages.build(ROOT, sources, tmp_path / "site", REPO)
    assert written[0] == "index.html"
    assert set(written) >= {"index.html", "docs/deployment.html", "lab/index.html"}
    index = (tmp_path / "site" / "index.html").read_text()
    assert 'href="docs/deployment.html"' in index
    assert 'href="docs/deployment.html#postgresql"' in index
    lab = (tmp_path / "site" / "lab" / "index.html").read_text()
    assert 'href="../docs/deployment.html"' in lab
    deployment = (tmp_path / "site" / "docs" / "deployment.html").read_text()
    assert f'href="{REPO}/blob/main/deploy/nginx/yk-portal.conf"' in deployment
    assert 'id="under-a-path"' in deployment


def test_links_headings_and_raw_html(tmp_path):
    sources = write(
        tmp_path,
        {
            "README.md": "# Project\n\nSee [a](docs/a.md).\n",
            "docs/a.md": (
                "# Page A\n\n## Same\n\n## Same\n\n"
                "[b](sub/b.md#part) [file](notes.txt) [folder](sub/) [second](#same-1) "
                "[site](https://example.org/x.md) [home](../README.md) <b>bold?</b>\n"
            ),
            "docs/sub/b.md": "# Page B\n\n## Part\n",
            "docs/notes.txt": "text\n",
        },
    )
    build_pages.build(tmp_path, sources, tmp_path / "site", REPO, ref="dev")
    page = (tmp_path / "site" / "docs" / "a.html").read_text()
    assert hrefs(page) == [
        "sub/b.html#part",
        f"{REPO}/blob/dev/docs/notes.txt",
        f"{REPO}/tree/dev/docs/sub",
        "#same-1",
        "https://example.org/x.md",
        "../index.html",
    ]
    assert '<h2 id="same">Same</h2>' in page and '<h2 id="same-1">Same</h2>' in page
    assert "&lt;b&gt;bold?&lt;/b&gt;" in page and "<b>" not in page
    assert "<title>Page A · Project</title>" in page
    assert '<link rel="stylesheet" href="../style.css">' in page
    assert f'<a href="{REPO}/blob/dev/docs/a.md">docs/a.md</a>' in page
    assert "<script" not in page
    assert "Content-Security-Policy" in page
    assert (tmp_path / "site" / "style.css").exists()


@pytest.mark.parametrize(
    ("link", "problem"),
    [
        ("missing.md", "no such file"),
        ("b.md#nowhere", "no heading #nowhere in b.md"),
        ("#nowhere", "no heading #nowhere here"),
        ("../../outside.md", "outside the repository"),
    ],
)
def test_a_broken_link_stops_the_build(tmp_path, link, problem):
    sources = write(tmp_path, {"a.md": f"# A\n\n[x]({link})\n", "b.md": "# B\n"})
    with pytest.raises(build_pages.BuildError, match=re.escape(f"a.md: {link}: {problem}")):
        build_pages.build(tmp_path, sources, tmp_path / "site", REPO)
    assert not (tmp_path / "site").exists()


def test_only_an_earlier_build_is_replaced(tmp_path):
    sources = write(tmp_path, {"README.md": "# P\n"})
    other = tmp_path / "other"
    other.mkdir()
    (other / "keep.txt").write_text("mine")
    with pytest.raises(build_pages.BuildError, match="isn't an earlier build"):
        build_pages.build(tmp_path, sources, other, REPO)
    assert (other / "keep.txt").read_text() == "mine"

    site = tmp_path / "site"
    build_pages.build(tmp_path, sources, site, REPO)
    (site / "stale.html").write_text("old")
    build_pages.build(tmp_path, sources, site, REPO)
    assert not (site / "stale.html").exists()
    assert (site / "index.html").exists()


@pytest.mark.parametrize(
    ("source", "page"),
    [
        ("README.md", "index.html"),
        ("lab/README.md", "lab/index.html"),
        ("docs/deployment.md", "docs/deployment.html"),
    ],
)
def test_page_paths(source, page):
    assert build_pages.page_path(source) == page
