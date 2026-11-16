#!/usr/bin/env bash
# Lighthouse against the production preview (npm run build && npx astro preview --port 4322).
# Usage: bash scripts/lighthouse.sh [mobile|desktop]   -> JSON reports in $TEMP/lh, summary on stdout
EDGE="C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe"
# chrome-launcher cannot read Edge's debugging port, so start Edge here and hand Lighthouse the port.
"$EDGE" --headless=new --no-first-run --disable-sync --remote-debugging-port=9444 --user-data-dir="$TEMP/lh-profile-$RANDOM" about:blank >/dev/null 2>&1 &
edge_pid=$!; sleep 3
preset="${1:-mobile}"; mkdir -p "$TEMP/lh"; out="$(cygpath -w "$TEMP/lh")"
flags=(); [ "$preset" = desktop ] && flags=(--preset=desktop)
for entry in home: blog:blog/ writeups:writeups/ research:research/ projects:projects/ about:about/ reader:writeups/hackthebox/sherlocks/htb-sherlock-rogueone/; do
  name="${entry%%:*}"; path="${entry#*:}"
  npx -y lighthouse "http://localhost:4322/$path" "${flags[@]}" --quiet --output=json \
    --output-path="$out/$name-$preset.json" --port=9444 >/dev/null 2>&1
  node -e "
    const r=JSON.parse(require('fs').readFileSync(process.argv[1],'utf8'));const c=r.categories,a=r.audits;
    const s=k=>Math.round(c[k].score*100);
    const fails=Object.values(c).flatMap(x=>x.auditRefs).map(x=>a[x.id]).filter(x=>x.score!==null&&x.score<0.9&&x.scoreDisplayMode==='binary').map(x=>x.id);
    console.log(process.argv[2].padEnd(9),'perf',s('performance'),'a11y',s('accessibility'),'bp',s('best-practices'),'seo',s('seo'),
      '| LCP',a['largest-contentful-paint'].displayValue,'CLS',a['cumulative-layout-shift'].displayValue,'TBT',a['total-blocking-time'].displayValue,
      '| fails:',[...new Set(fails)].join(',')||'none');" "$out/$name-$preset.json" "$name"
done
kill $edge_pid 2>/dev/null
