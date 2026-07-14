# TypeSec Book Build Notes

The canonical command is:

```sh
docs/book/build.sh
```

See `docs/book/PUBLISH.md` for the complete artifact, validation, and delivery
contract.

## Cover

The canonical 1024x1536 cover is `cover/typesec-cover.png`. Its source
headboard, generated portrait art, First Pair Press publisher mask, prompt, and
deterministic composition command are documented in `cover/README.md`.

Recompose the exact typography and publisher seal with:

```sh
uv run --no-project --with pillow python cover/make-cover.py
```

The composer owns the visible title `Typesec`, subtitle
`Type-Level Security for Agentic AI`, and the sole author line
`Alexy Khrabrov`. `book.build.json` installs the same PNG as the first,
unnumbered PDF page and as the EPUB cover image. `docs/book/cover.md` references
it for browser HTML.

## Mermaid Diagrams

The manuscript carries inline `mermaid` blocks. The shared builder passes
`docs/book/mermaid.lua` to Pandoc; the filter calls `mmdc` and uses
`docs/book/puppeteer-config.json` for headless Chromium. Edit diagrams in
`docs/book/typesec.md`; generated diagram images are build intermediates.

## Metadata and EPUB Layout

Stable metadata lives in `docs/book/metadata.yaml`. The visible title remains
`Typesec`, while the OPF catalog title and delivery name are versioned. The
creator must be exactly `Alexy Khrabrov` and the publisher must be
`First Pair Press`.

`docs/book/fix_epub_layout.sh` orders the EPUB spine as image cover, visible
navigation/TOC, then manuscript. `docs/book/check_epub_metadata.sh` validates
that order, the metadata, the 1024x1536 cover wrapper, and byte identity between
the packaged cover and `cover/typesec-cover.png` before MOBI generation.

## Output

Stable PDF, EPUB, MOBI, single-file HTML, chapter HTML, and `VERSION.md` outputs
live in `docs/book/dist/`. Versioned delivery paths are generated symlinks to
those stable artifacts. A successful canonical build finishes with the shared
PDF/EPUB/HTML and version-marker contracts passing.
