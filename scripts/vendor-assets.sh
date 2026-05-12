#!/usr/bin/env bash
# Re-downloads the frontend assets served from internal/web/static/vendor/.
#
# To bump a version: edit the entry below, re-run this script, commit the
# updated file(s), and update the <script>/<link> filename in
# internal/web/templates/layout.html if the version is part of the filename.

set -euo pipefail

vendor_dir="$(dirname "$0")/../internal/web/static/vendor"
mkdir -p "$vendor_dir"
cd "$vendor_dir"
rm -f -- *.js *.css

assets=(
  "tailwindcss-browser-4.3.0.js               https://cdn.jsdelivr.net/npm/@tailwindcss/browser@4.3.0"
  "basecoat-0.3.11.min.css                    https://cdn.jsdelivr.net/npm/basecoat-css@0.3.11/dist/basecoat.cdn.min.css"
  "basecoat-0.3.11.min.js                     https://cdn.jsdelivr.net/npm/basecoat-css@0.3.11/dist/js/all.min.js"
  "htmx-2.0.6.min.js                          https://cdn.jsdelivr.net/npm/htmx.org@2.0.6/dist/htmx.min.js"
  "htmx-ext-sse-2.2.4.min.js                  https://cdn.jsdelivr.net/npm/htmx-ext-sse@2.2.4/sse.min.js"
  "lucide-0.545.0.min.js                      https://cdn.jsdelivr.net/npm/lucide@0.545.0/dist/umd/lucide.min.js"
  "highlight-11.11.1-github.min.css           https://cdn.jsdelivr.net/gh/highlightjs/cdn-release@11.11.1/build/styles/github.min.css"
  "highlight-11.11.1-github-dark.min.css      https://cdn.jsdelivr.net/gh/highlightjs/cdn-release@11.11.1/build/styles/github-dark.min.css"
  "highlight-11.11.1.min.js                   https://cdn.jsdelivr.net/gh/highlightjs/cdn-release@11.11.1/build/highlight.min.js"
)

for entry in "${assets[@]}"; do
  read -r file url <<<"$entry"
  echo "  $file"
  curl -sSfLo "$file" "$url"
done

echo "Done. ${#assets[@]} assets refreshed in $(pwd)."
