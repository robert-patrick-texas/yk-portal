"""Build the project's Markdown documents into a static HTML site for GitHub Pages.

    uv run --only-group pages scripts/build_pages.py [OUTPUT]      (default: _site)

Every Markdown file git tracks becomes a page: README.md is index.html (in a
directory, that directory's index.html), any other NAME.md is NAME.html.
Links between documents point to their pages, links to other files of the
repository to the files on GitHub, and a link to a file or heading that
doesn't exist stops the build: the site has no broken links. Raw HTML in the
Markdown is shown as text. Each page links to the repository at the top, and
has an index on the left (below the page on narrow screens) of the
documents, with the sections of the one shown. The pages have no scripts, and
a Content-Security-Policy that allows only the site's own stylesheet.

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
header {
  display: flex; flex-wrap: wrap; gap: 0.5rem 1.25rem; align-items: baseline;
  padding: 0.75rem 1rem; border-bottom: 1px solid var(--border);
}
header .site { margin-right: auto; color: var(--text); font-weight: 600; text-decoration: none; }
.layout { display: grid; grid-template-columns: minmax(0, 1fr); max-width: 78rem; margin: 0 auto; }
main { max-width: 52rem; padding: 1rem 1rem 2rem; }
/* The index: below the page on narrow screens, reached by the header's Contents link. */
nav.index { order: 2; padding: 1rem; border-top: 1px solid var(--border); font-size: 0.875rem; }
nav.index ul { list-style: none; margin: 0; padding: 0; }
nav.index li { margin: 0.2rem 0; }
nav.index a { color: var(--text); text-decoration: none; }
nav.index a:hover { text-decoration: underline; }
nav.index a[aria-current="page"] { font-weight: 600; }
nav.index .sections {
  margin: 0.3rem 0 0.6rem 0.25rem; padding-left: 0.75rem; border-left: 2px solid var(--border);
}
nav.index .sections a { color: var(--muted); }
nav.index .sections .depth-1 { padding-left: 0.85rem; }
@media (min-width: 60rem) {
  .layout { grid-template-columns: 17rem minmax(0, 1fr); }
  nav.index {
    order: 0; position: sticky; top: 0; align-self: start; max-height: 100vh; overflow-y: auto;
    border-top: 0; border-right: 1px solid var(--border);
  }
  header .contents { display: none; }
}
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
footer {
  max-width: 78rem; margin: 0 auto; padding: 1rem; color: var(--muted); font-size: 0.875rem;
  border-top: 1px solid var(--border);
}
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
<header>
<a class="site" href="{root}index.html">{site}</a>
<a class="contents" href="#index">Contents</a>
<a class="repository" href="{repo_url}">{repo_name} on GitHub</a>
</header>
<div class="layout">
<nav id="index" class="index" aria-label="Documents">
{index}</nav>
<main>
{body}</main>
</div>
<footer>
<p>From <a href="{source}">{path}</a>, in <a href="{repo_url}">{repo_name}</a>.</p>
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
    # Every heading but the title: (level, ID, text).
    sections: list[tuple[int, str, str]] = field(default_factory=list)

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
        headings = _headings(tokens)
        # The first level-1 heading is the title; every other heading is a section.
        first = next((i for i, (level, _, _) in enumerate(headings) if level == 1), None)
        title = headings[first][2] if first is not None else source
        sections = [h for i, h in enumerate(headings) if i != first]
        ids = {ident for _, ident, _ in headings}
        pages[source] = Page(source, tokens, title, ids, sections)
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
        title = page.title if page.output == "index.html" else f"{page.title} · {site}"
        text = PAGE.format(
            title=html.escape(title),
            root=up,
            site=html.escape(site),
            index=_index(pages.values(), page, up),
            body=md.renderer.render(page.tokens, md.options, {}),
            source=html.escape(f"{repo_url}/blob/{ref}/{page.source}"),
            path=html.escape(page.source),
            repo_url=html.escape(repo_url),
            repo_name=html.escape(urlsplit(repo_url).path.strip("/") or repo_url),
        )
        target = output / page.output
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8")
    (output / "style.css").write_text(CSS, encoding="utf-8")
    (output / ".nojekyll").write_text("")
    return [page.output for page in pages.values()]


def _headings(tokens: list[Token]) -> list[tuple[int, str, str]]:
    """Each heading's level, ID and text, the text without its Markdown."""
    headings = []
    for i, token in enumerate(tokens):
        if token.type == "heading_open":
            text = "".join(
                child.content
                for child in tokens[i + 1].children or []
                if child.type in ("text", "code_inline")
            )
            headings.append((int(token.tag[1]), str(token.attrs.get("id", "")), text))
    return headings


def _index(pages, current: Page, up: str) -> str:
    """Every document, and under the one shown, its sections: the top level of its
    headings and the level below."""
    items = []
    for page in pages:
        href = html.escape(up + page.output)
        if page is not current:
            items.append(f'<li><a href="{href}">{html.escape(page.title)}</a></li>\n')
            continue
        items.append(f'<li><a href="{href}" aria-current="page">{html.escape(page.title)}</a>\n')
        if page.sections:
            top = min(level for level, _, _ in page.sections)
            items.append('<ul class="sections">\n')
            items.extend(
                f'<li class="depth-{max(level - top, 0)}">'
                f'<a href="#{html.escape(ident)}">{html.escape(text)}</a></li>\n'
                for level, ident, text in page.sections
                if level <= top + 1
            )
            items.append("</ul>\n")
        items.append("</li>\n")
    return '<ul class="pages">\n' + "".join(items) + "</ul>\n"


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
