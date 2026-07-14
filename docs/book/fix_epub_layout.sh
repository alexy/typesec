#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 1 || $# -gt 2 ]]; then
  echo "usage: $0 path/to/book.epub [library-title]" >&2
  exit 2
fi

epub="$1"
library_title="${2:-}"

if [[ ! -f "$epub" ]]; then
  echo "EPUB not found: $epub" >&2
  exit 2
fi

tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

workdir="$tmpdir/work"
mkdir -p "$workdir"
unzip -q "$epub" -d "$workdir"

content_opf="$workdir/EPUB/content.opf"
fixed="$tmpdir/fixed.epub"

perl -0pi -e '
  s#\s*<itemref idref="nav"(?: linear="no")? />##g;
  s#<spine toc="ncx">\s*<itemref idref="cover_xhtml" />#<spine toc="ncx">\n    <itemref idref="cover_xhtml" />\n    <itemref idref="nav" linear="no" />#s;
' "$content_opf"

if [[ -n "$library_title" ]]; then
  LIBRARY_TITLE="$library_title" perl -0pi -e '
    my $title = $ENV{LIBRARY_TITLE};
    s{<meta\s+refines="\#epub-title-1"\s+property="file-as">.*?</meta>\s*}{}s;
    s{<dc:title([^>]*)>.*?</dc:title>}{<dc:title$1>$title</dc:title>\n    <meta refines="#epub-title-1" property="file-as">$title</meta>}s;
  ' "$content_opf"
fi

(
  cd "$workdir"
  zip -X0q "$fixed" mimetype
  zip -Xrq "$fixed" META-INF EPUB
)

mv "$fixed" "$epub"
echo "EPUB layout fixed: $epub"
