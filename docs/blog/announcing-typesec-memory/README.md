# Announcing TypeSec Memory

This directory contains the canonical Markdown announcement, its generated
headboard, and the import-ready TextPack for Ulysses and Omnighost/Ghost.

## Headboard

`assets/typesec-memory-headboard.png` was generated at 1536×1024 with Codex's
built-in image-generation tool using this prompt:

> Create a museum-quality, painterly 3:2 editorial panorama for an
> “Announcing TypeSec Memory” blog headboard. Show the lineage of one document
> in a seamless left-to-right progression: a Cicero-era Roman papyrus; the
> scroll collections and monumental reading hall of ancient Alexandria; a
> medieval Alpine monastery scriptorium where a monk copies the work into a
> codex; Petrarch in fourteenth-century Venice studying a handwritten
> manuscript whose turning page transitions into a later Venetian incunable;
> and a modern slim tablet resembling an iPad, without an Apple logo,
> displaying a LaTeX source editor beside its clean typeset document. Follow
> the document through every era with a restrained crimson-and-gold provenance
> thread passing through seals, shelf marks, marginalia, and bindings. Evolve
> the setting from papyrus ochre and Alexandrian limestone through monastic
> umber and Alpine blue to Venetian vermilion, lagoon teal, and cool digital
> light. Render historically grounded papyrus, marble, wood, parchment, iron
> clasps, linen paper, movable-type ink, and glass. Keep all five eras distinct
> but visually unified. No title, captions, logos, brand marks, watermark,
> fantasy objects, holograms, steampunk machinery, or modern items in the
> historical sections. Avoid prominent small text or gibberish on the tablet.

Petrarch died before the age of incunabula. The composition therefore shows
him handling a manuscript whose page transitions into a later Venetian
incunable rather than depicting a printed book as his contemporary object.

## TextPack

Build the Omnighost TextPack with the centralized FirstPair flow. This may
create a source commit to stamp `info.json` with `omnighost-textpack-v1`
provenance, so follow `~/src/firstpair/AGENTS.md` and get explicit permission
before running it:

```sh
BLOG_DOMAIN=querygraph.ai \
BLOG_TAGS='querygraph,typesec,memory,responsible-ai,agents' \
BLOG_EXCERPT='Marciana makes AI memory privacy-first with typed capabilities, provenance, temporal history, TypeDID accountability, and durable QueryGraph persistence.' \
python3 ~/src/firstpair/publishing/scripts/textpack.py \
  docs/blog/announcing-typesec-memory \
  --blog "$BLOG_DOMAIN" \
  --slug announcing-typesec-memory \
  --tags "$BLOG_TAGS" \
  --excerpt "$BLOG_EXCERPT"
```

The output lands at
`docs/blog/announcing-typesec-memory/dist/announcing-typesec-memory.textpack`.
