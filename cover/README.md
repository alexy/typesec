# Typesec Cover

The final cover is `typesec-cover.png`. It uses the TypeSec blog headboard as
its visual source and the reusable First Pair Press publisher mask from
`~/src/firstpair/logo/firstpair-publisher-mask.png`.

- Source headboard: `typesec-blog-headboard.png`
- Source URL: <https://digitalpress.fra1.cdn.digitaloceanspaces.com/cz6pt2z/2026/07/Typesec.png>
- Generated portrait art: `typesec-cover-art.png`
- Final composed cover: `typesec-cover.png`

The portrait-art prompt was:

> Recompose the landscape TypeSec headboard as 2:3 portrait full-bleed cover
> art. Preserve the monochrome British espionage atmosphere, Westminster and
> Big Ben, Thames reflections, map texture, classic cars, trench-coated
> agents, and restrained red accents. Remove every word, label, stamp, logo,
> and license-plate text. Leave calm dark upper and lower regions for exact
> typography and a publisher mark. Add no unrelated subjects.

The generated art intentionally contains no lettering. Exact title, subtitle,
author, and publisher-seal placement are reproducible with:

```sh
uv run --no-project --with pillow python cover/make-cover.py
```
