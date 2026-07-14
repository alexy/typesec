# TypeSec Book Publishing Skill

Use this runbook when updating, rebuilding, validating, delivering, or publishing
the TypeSec book in its current shape.

## Source Layout

- Manuscript: `docs/book/typesec.md`
- Final cover: `cover/typesec-cover.png`
- Cover recipe and source assets: `cover/README.md`
- Browser-reader cover wrapper: `docs/book/cover.md`
- EPUB metadata: `docs/book/metadata.yaml`
- Build script: `docs/book/build.sh`
- Shared configuration: `book.build.json`
- EPUB layout fixer: `docs/book/fix_epub_layout.sh`
- EPUB validator: `docs/book/check_epub_metadata.sh`
- Final artifacts: `docs/book/dist/`

The book directory is `docs/book/` in this repository. There is no top-level
`book/` directory in the current tree.

## Current Artifact Contract

The stable deliverables are:

- `docs/book/dist/typesec.pdf`
- `docs/book/dist/typesec.epub`
- `docs/book/dist/typesec.mobi`
- `docs/book/dist/VERSION.md`

The Kindle-facing EPUB path is generated from `title_stem` in
`docs/book/metadata.yaml` and `[workspace.package].version` in `Cargo.toml`:

```text
typesec (<workspace-version>).epub
```

That versioned path must be a symlink to the stable EPUB:

```text
docs/book/dist/typesec (<workspace-version>).epub -> typesec.epub
```

Track the stable EPUB, PDF, MOBI, and `VERSION.md`. The versioned EPUB is a
generated symlink and `.gitignore` ignores future versioned EPUB names matching
`docs/book/dist/* (*).epub`.

`VERSION.md` must contain:

```yaml
kindle_name: typesec (<workspace-version>)
built_at: YYYY-MM-DD
epub_file: typesec.epub
kindle_link: typesec (<workspace-version>).epub
```

## Metadata Rules

The visible book title stays clean:

```text
Typesec
```

The Kindle/catalog title is versioned:

```text
typesec (<workspace-version>)
```

Keep those surfaces separate:

- Cover, NCX, navigation title, and visible table of contents: `Typesec`
- Cover subtitle: `Type-Level Security for Agentic AI`
- Cover and package author: `Alexy Khrabrov` only
- OPF `dc:title` and title-sort metadata: `typesec (<workspace-version>)`
- Upload/delivery filename: `typesec (<workspace-version>).epub`
- Dist marker: `VERSION.md`

Do not put the package version on the visible cover. The deterministic composer
owns its exact title, subtitle, author, and First Pair Press seal; the shared
builder owns the versioned Kindle/catalog metadata. Keep stable metadata in
`docs/book/metadata.yaml`: visible title, subtitle, author, language, publisher,
rights, and `title_stem`. The build date may be dynamic, but those descriptive
fields should stay in source control.

## Cover Rules

The canonical cover is the 1024x1536 raster image
`cover/typesec-cover.png`. It is composed from the source headboard, generated
portrait artwork, and the reusable First Pair Press publisher mask documented
in `cover/README.md`. Rebuild it deterministically with:

```sh
uv run --no-project --with pillow python cover/make-cover.py
```

`book.build.json` installs the image as page 1 of the PDF and as the EPUB
`cover-image`. `docs/book/cover.md` is the browser-HTML title-page wrapper and
must reference the same image. Keep the lettering out of generated portrait
art; `cover/make-cover.py` owns the exact white-on-dark title, subtitle,
`ALEXY KHRABROV` author line, and First Pair Press seal.

After merging, the PDF should have an image-only, unnumbered cover on page 1
and the numbered Contents page on page 2. The EPUB validator requires the
packaged cover bytes to match `cover/typesec-cover.png` exactly.

Keep code blocks compact in EPUB and MOBI through `docs/book/epub.css`. Pandoc's
syntax highlighting emits one `<span>` per source line and represents
intentional blank source lines as empty spans; reader defaults can turn those
empty spans into large gaps. The stylesheet overrides `div.sourceCode`, `pre`,
`pre code`, `pre > code.sourceCode > span`, and
`pre > code.sourceCode > span:empty` so code uses tight line-height and empty
source-line spans do not render as extra vertical whitespace.

## Build

From the repository root:

```sh
docs/book/build.sh
```

The repository wrapper delegates to
`~/src/firstpair/publishing/scripts/build-library-book.sh`. The checked-in
`book.build.json` owns the TypeSec paths, Mermaid filter environment, EPUB
layout repair hook, and local metadata validator; FirstPair owns rendering,
versioned links, the complete manifest, and mandatory artifact verification.

The shared build:

1. Reads the workspace version from `Cargo.toml`.
2. Reads `title_stem` from `docs/book/metadata.yaml`.
3. Computes `kindle_name`, for example `typesec (0.9.0)`.
4. Writes `docs/book/dist/VERSION.md`.
5. Builds a standalone PDF page from `cover/typesec-cover.png`.
6. Builds the body PDF with table of contents and numbered sections.
7. Merges the raster cover page before the body in `docs/book/dist/typesec.pdf`.
8. Builds `docs/book/dist/typesec.epub` with the same PNG as its cover image,
   `--css docs/book/epub.css`, and
   `--epub-title-page=false`.
9. Runs `fix_epub_layout.sh` to repair Pandoc EPUB defaults.
10. Creates the versioned artifact symlinks and full `VERSION.md` manifest.
11. Runs `check_epub_metadata.sh`.
12. Builds single-file and chapter HTML, packaging the cover with the chapters.
13. Converts the EPUB to `docs/book/dist/typesec.mobi` and runs the shared
    PDF/EPUB/HTML artifact contract.

Calibre is expected at:

```sh
/Applications/calibre.app/Contents/MacOS/ebook-convert
```

Use that app-bundle path unless the application bundle changes.

## EPUB Layout Fix

`docs/book/fix_epub_layout.sh` rewrites the generated EPUB so that:

- Pandoc's image-cover XHTML is first in the spine.
- The navigation document follows it and is marked `linear="no"`.
- The first manuscript chapter follows the navigation document.
- OPF `dc:title` and title-sort metadata are set to the Kindle/catalog title.

Keep `--epub-title-page=false` in the Pandoc EPUB command. Without it, Pandoc can
generate an extra empty `EPUB/text/title_page.xhtml` before the custom cover.
Calibre may still inspect or convert an EPUB with weak metadata, but Kindle
delivery is less forgiving. Treat missing title/creator/language/date fields,
`UNTITLED`, `Unknown`, an empty generated title page, a nav-first spine, or a
missing/mismatched image cover as release blockers.

## Required Validation

After every build, run:

```sh
expected_title=$(awk -F': ' '/^kindle_name:/ { print $2 }' docs/book/dist/VERSION.md)
docs/book/check_epub_metadata.sh docs/book/dist/typesec.epub "$expected_title"
```

The validator rejects:

- Missing OPF title, creator, language, date, or modified metadata.
- Missing title-sort metadata.
- Fallback `UNTITLED` or `Unknown` metadata.
- Navigation or NCX titles that do not say `Typesec`.
- A spine that does not put the image cover before the nav item.
- A generated empty `title_page.xhtml`.
- Missing cover metadata, the wrong 1024x1536 SVG wrapper, or packaged cover
  bytes that differ from `cover/typesec-cover.png`.
- Creator metadata other than `Alexy Khrabrov`, or publisher metadata other
  than `First Pair Press`.
- Missing compact code-block rules in the EPUB stylesheet.
- Missing stable EPUB.
- A stable EPUB that differs from the canonical EPUB.
- A missing or non-symlink versioned Kindle EPUB.
- A versioned symlink that does not point to `typesec.epub`.
- A missing or incomplete `VERSION.md`.

Also verify the PDF cover and numbering:

```sh
pdftotext -f 1 -l 1 docs/book/dist/typesec.pdf -
pdftotext -f 2 -l 2 docs/book/dist/typesec.pdf -
```

Expected result: page 1 has a raster image and no extractable page number;
page 2 contains Contents and body numbering starts at `1`. For visual QA,
rasterize page 1 with `pdftoppm` and inspect the resulting PNG.

Check the versioned EPUB link:

```sh
ls -l docs/book/dist
kindle_link=$(awk -F': ' '/^kindle_link:/ { print $2 }' docs/book/dist/VERSION.md)
readlink "docs/book/dist/$kindle_link"
```

Expected result:

```text
typesec.epub
```

Optional Calibre metadata check:

```sh
/Applications/calibre.app/Contents/MacOS/ebook-meta docs/book/dist/typesec.epub
```

Expected title and title sort:

```text
typesec (<workspace-version>)
```

If Calibre reports a permissions error while rendering metadata under
`~/Library/Preferences/calibre`, the metadata lines may still print. For a full
MOBI rebuild, rerun `docs/book/build.sh` with normal filesystem access.

## Blog Posts

Each release also ships a blog post. Posts use the per-post layout
`docs/blog/<name>/`:

- `post.md` — the canonical post (prose reflowed to one line per paragraph;
  diagrams referenced as `![caption](diagrams/<name>.png)`).
- `diagrams/<name>.mmd` — the Mermaid source for each diagram.
- `diagrams/<name>.png` — the rendered image (white background, 2×) committed
  alongside its source.

**Always create a `.textpack` for each blog post**, following
[`TEXTPACK.md`](../../TEXTPACK.md) (repo root). That guide is the required
last-mile step: it reflows the prose, renders the Mermaid diagrams to PNG, and
bundles the text plus image assets into a single `.textpack` that imports cleanly
into Ulysses/Ghost (including on iOS, where `mermaid` blocks and relative image
paths do not render).

The built `.textpack` is **committed next to the post** under
`docs/blog/<name>/dist/` (mirroring `docs/book/dist/`), so each release's
ready-to-import bundle is versioned with the post. Commit only the `.textpack`,
not the unzipped `.textbundle/`. Unlike the book, blog posts do not use the
build-time Mermaid filter — their PNGs are committed so the `.textpack` bundler
can pick them up directly.

## Delivery

The build maintains a versioned delivery link for **both** the EPUB and the PDF
in `dist/`, stamped `stem (<version>-<short-commit>)` (e.g.
`typesec (0.11.0-28b8ba).epub` / `.pdf`) — the commit hash makes each built
artifact traceable to a source state, while the book's visible title/cover stays
clean. `VERSION.md` records both as `epub_link` and `pdf_link`. The versioned
links are git-ignored (build-time, local).

For local iCloud delivery, always publish **both** stamped artifacts to
`~/icloud/books`, copying each link by name (resolving the symlink to a real
file):

```sh
epub_link=$(awk -F': ' '/^epub_link:/ { print $2 }' docs/book/dist/VERSION.md)
pdf_link=$(awk -F': ' '/^pdf_link:/  { print $2 }' docs/book/dist/VERSION.md)
cp "docs/book/dist/$epub_link" "$HOME/icloud/books/$epub_link"
cp "docs/book/dist/$pdf_link"  "$HOME/icloud/books/$pdf_link"
```

This produces two regular files preserving the stamped filename:

```text
~/icloud/books/typesec (<version>-<short-commit>).epub
~/icloud/books/typesec (<version>-<short-commit>).pdf
```

Verify by exact path (do not list the directory):

```sh
cmp "docs/book/dist/$epub_link" "$HOME/icloud/books/$epub_link"
cmp "docs/book/dist/$pdf_link"  "$HOME/icloud/books/$pdf_link"
```

Do not treat iCloud delivery as a broad directory-access task. On this Mac,
listing `~/icloud/books` can fail with `Operation not permitted` even when a
direct probe or copy to the exact destination file works. Derive the current
filename from `docs/book/dist/VERSION.md`, then use exact-path `stat`, `cmp`,
or `cp` against `~/icloud/books/<kindle_link>`. If Codex is running in a
workspace sandbox, the exact `cp` may still require an approved/escalated
command because `~/icloud/books` is outside the repository writable root; ask
only for that specific write, not for a general iCloud browsing permission.

Direct CLI mail to Send to Kindle has been less reliable than artifact delivery
and queue inspection. If email delivery is requested, do not trust command
success alone; report sender identity plus queue/delivery state.

## Git Delivery

When a publishing change affects source, metadata, build scripts, or generated
deliverables, commit the source changes and rebuilt artifacts together.

Before committing:

```sh
git status --short
git diff --stat
expected_title=$(awk -F': ' '/^kindle_name:/ { print $2 }' docs/book/dist/VERSION.md)
docs/book/check_epub_metadata.sh docs/book/dist/typesec.epub "$expected_title"
```

The normal pushed set for book artifact changes includes:

- `docs/book/*.md` source or note changes that were edited.
- `docs/book/build.sh`, `fix_epub_layout.sh`, or `check_epub_metadata.sh` if
  the pipeline changed.
- `docs/book/dist/VERSION.md`
- `docs/book/dist/typesec.pdf`
- `docs/book/dist/typesec.epub`
- `docs/book/dist/typesec.mobi`
- A versioned `docs/book/dist/typesec (<workspace-version>).epub` symlink only
  when its tracked target or mode changes. Future generated versioned EPUB names
  are ignored by `.gitignore`.

Leave unrelated `.codex-artifacts/` files untracked unless the user explicitly
asks to include them.

After commit:

```sh
git push
```

The current remote should be `querygraph/typesec`.
