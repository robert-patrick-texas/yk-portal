"""Build the project's Markdown documents into a static HTML site for GitHub Pages.

    uv run --only-group pages scripts/build_pages.py [OUTPUT]      (default: _site)

Every Markdown file git tracks becomes a page: README.md is index.html (in a
directory, that directory's index.html), any other NAME.md is NAME.html.
Links between documents point to their pages, links to other files of the
repository to the files on GitHub, and a link to a file or heading that
doesn't exist stops the build: the site has no broken links. Raw HTML in the
Markdown is shown as text. The pages have no scripts, and a
Content-Security-Policy that allows only the site's own stylesheet.

.github/workflows/pages.yml runs it and publishes OUTPUT on each push to main.
"""

import html
import os
import posixpath
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import unquote, urlsplit

from markdown_it import MarkdownIt
from markdown_it.token import Token
from mdit_py_plugins.anchors import anchors_plugin

ROOT = Path(__file__).resolve().parent.parent
# Left in OUTPUT, so a later build may replace it and nothing else.
MARKER = ".build-pages"

CSS = """\
:root {
  color-scheme: light dark;
  --text: #1f2328; --muted: #59636e; --bg: #ffffff; --surface: #f6f8fa;
  --border: #d1d9e0; --link: #0969da;
}
@media (prefers-color-scheme: dark) {
  :root {
    --text: #e6edf3; --muted: #9198a1; --bg: #0d1117; --surface: #151b23;
    --border: #3d444d; --link: #4493f8;
  }
}
* { box-sizing: border-box; }
body {
  margin: 0; background: var(--bg); color: var(--text);
  font: 16px/1.6 system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
}
a { color: var(--link); }
header, main, footer { max-width: 52rem; margin: 0 auto; padding: 0 1rem; }
header { padding-top: 1rem; padding-bottom: 1rem; border-bottom: 1px solid var(--border); }
header a { color: var(--text); font-weight: 600; text-decoration: none; }
main { padding-top: 1rem; padding-bottom: 2rem; }
h1, h2, h3 { line-height: 1.25; }
h1 { font-size: 2rem; }
h2 { padding-bottom: 0.3rem; border-bottom: 1px solid var(--border); }
code, pre {
  font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 0.875em;
}
code { background: var(--surface); padding: 0.1em 0.3em; border-radius: 4px; }
pre { background: var(--surface); padding: 0.75rem 1rem; border-radius: 6px; overflow-x: auto; }
pre code { background: none; padding: 0; }
table { display: block; overflow-x: auto; border-collapse: collapse; margin: 1rem 0; }
th, td {
  border: 1px solid var(--border); padding: 0.375rem 0.75rem; text-align: left; vertical-align: top;
}
th { background: var(--surface); }
blockquote {
  margin: 1rem 0; padding: 0 1rem; color: var(--muted); border-left: 0.25rem solid var(--border);
}
hr { border: 0; border-top: 1px solid var(--border); margin: 1.5rem 0; }
footer { padding-bottom: 2rem; color: var(--muted); font-size: 0.875rem; }
footer ul { padding-left: 1.25rem; }
"""

PAGE = """\
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'self'; \
base-uri 'none'; form-action 'none'">
<title>{title}</title>
<link rel="stylesheet" href="{root}style.css">
</head>
<body>
<header><a href="{root}index.html">{site}</a></header>
<main>
{body}</main>
<footer>
<p>From <a href="{source}">{path}</a>. Documents:</p>
<ul>
{documents}</ul>
</footer>
</body>
</html>
"""


class BuildError(Exception):
    """A document links to a file or heading that doesn't exist."""


@dataclass
class Page:
    source: str  # the Markdown file, relative to the repository's root
    tokens: list[Token]
    title: str
    ids: set[str] = field(default_factory=set)

    @property
    def output(self) -> str:
        return page_path(self.source)


def page_path(source: str) -> str:
    """The page for a Markdown file: README.md is its directory's index.html."""
    directory, name = posixpath.split(source)
    name = "index.html" if name.lower() == "readme.md" else name[:-3] + ".html"
    return posixpath.join(directory, name)


def markdown() -> MarkdownIt:
    """CommonMark with GitHub's tables and strikethrough, and its heading IDs. Raw HTML
    is escaped."""
    md = MarkdownIt("commonmark", {"html": False}).enable(["table", "strikethrough"])
    return md.use(anchors_plugin, min_level=1, max_level=6)


def build(
    root: Path, sources: list[str], output: Path, repo_url: str, ref: str = "main"
) -> list[str]:
    """Write the site for SOURCES, Markdown files relative to ROOT, into OUTPUT.

    Args:
        repo_url: The repository on GitHub, for links to files that aren't pages.
        ref: The branch those links name.

    Returns:
        The pages written, relative to OUTPUT.

    Raises:
        BuildError: A link names a file or heading that doesn't exist; nothing is written.
    """
    md = markdown()
    pages = {}
    for source in sorted(sources, key=lambda s: (page_path(s) != "index.html", s)):
        tokens = md.parse((root / source).read_text(encoding="utf-8"))
        ids = {t.attrs["id"] for t in tokens if t.type == "heading_open" and "id" in t.attrs}
        pages[source] = Page(source, tokens, _title(tokens) or source, {str(i) for i in ids})
    errors = []
    for page in pages.values():
        for token in _links(page.tokens):
            href = str(token.attrs["href"])
            try:
                token.attrSet("href", _rewrite(href, page, pages, root, repo_url, ref))
            except BuildError as e:
                errors.append(f"{page.source}: {href}: {e}")
    if errors:
        raise BuildError("\n".join(errors))

    _prepare(output)
    site = next(iter(pages.values())).title if pages else "Documents"
    for page in pages.values():
        up = "../" * page.output.count("/")
        documents = "".join(
            f'<li><a href="{up}{html.escape(p.output)}">{html.escape(p.title)}</a></li>\n'
            for p in pages.values()
        )
        title = page.title if page.output == "index.html" else f"{page.title} · {site}"
        text = PAGE.format(
            title=html.escape(title),
            root=up,
            site=html.escape(site),
            body=md.renderer.render(page.tokens, md.options, {}),
            source=html.escape(f"{repo_url}/blob/{ref}/{page.source}"),
            path=html.escape(page.source),
            documents=documents,
        )
        target = output / page.output
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8")
    (output / "style.css").write_text(CSS, encoding="utf-8")
    (output / ".nojekyll").write_text("")
    return [page.output for page in pages.values()]


def _title(tokens: list[Token]) -> str:
    """The text of the first level-1 heading."""
    for i, token in enumerate(tokens):
        if token.type == "heading_open" and token.tag == "h1":
            return tokens[i + 1].content
    return ""


def _links(tokens: list[Token]):
    for token in tokens:
        for child in token.children or []:
            if child.type == "link_open":
                yield child


def _rewrite(
    href: str, page: Page, pages: dict[str, Page], root: Path, repo_url: str, ref: str
) -> str:
    url = urlsplit(href)
    if url.scheme or url.netloc:
        return href  # another site
    fragment = unquote(url.fragment)
    if not url.path:
        if fragment and fragment not in page.ids:
            raise BuildError(f"no heading #{fragment} here")
        return href
    target = posixpath.normpath(posixpath.join(posixpath.dirname(page.source), unquote(url.path)))
    if target.startswith("../"):
        raise BuildError("outside the repository")
    if target in pages:
        if fragment and fragment not in pages[target].ids:
            raise BuildError(f"no heading #{fragment} in {target}")
        relative = posixpath.relpath(page_path(target), posixpath.dirname(page.output) or ".")
        return relative + (f"#{url.fragment}" if url.fragment else "")
    path = root / target
    if path.is_file() or path.is_dir():
        kind = "tree" if path.is_dir() else "blob"
        return f"{repo_url}/{kind}/{ref}/{target}" + (f"#{url.fragment}" if url.fragment else "")
    raise BuildError("no such file")


def _prepare(output: Path) -> None:
    """An empty OUTPUT: new, or a previous build's, never another directory."""
    if output.exists():
        if not (output / MARKER).exists() and any(output.iterdir()):
            raise BuildError(f"{output} isn't empty and isn't an earlier build: not replacing it")
        shutil.rmtree(output)
    output.mkdir(parents=True)
    (output / MARKER).write_text("Written by scripts/build_pages.py; replaced by each build.\n")


def _git(*args: str) -> str:
    result = subprocess.run(  # noqa: S603 - git, with fixed arguments
        ["git", *args],  # noqa: S607 - git from PATH
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=True,
    )
    return result.stdout


def _repository() -> tuple[str, str]:
    """The repository's GitHub URL and branch: from GitHub Actions, or from git."""
    if os.environ.get("GITHUB_REPOSITORY"):
        server = os.environ.get("GITHUB_SERVER_URL", "https://github.com")
        url = f"{server}/{os.environ['GITHUB_REPOSITORY']}"
        return url, os.environ.get("GITHUB_REF_NAME") or "main"
    remote = _git("remote", "get-url", "origin").strip().removesuffix(".git")
    if remote.startswith("git@"):
        host, _, path = remote[4:].partition(":")
        remote = f"https://{host}/{path}"
    branch = _git("rev-parse", "--abbrev-ref", "HEAD").strip()
    return remote, branch if branch != "HEAD" else "main"


def main(argv: list[str]) -> int:
    if argv[:1] in (["-h"], ["--help"]) or len(argv) > 1:
        print(__doc__.split("\n\n")[1].strip(), file=sys.stdout if argv else sys.stderr)
        return 0 if argv[:1] in (["-h"], ["--help"]) else 2
    output = Path(argv[0]) if argv else ROOT / "_site"
    sources = _git("ls-files", "-z", "--", "*.md").split("\0")
    try:
        repo_url, ref = _repository()
        written = build(ROOT, [s for s in sources if s], output, repo_url, ref)
    except (BuildError, subprocess.CalledProcessError) as e:
        print(f"build_pages: {e}", file=sys.stderr)
        return 1
    print(f"Wrote {len(written)} pages to {output}: {', '.join(written)}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
