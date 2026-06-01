**Screenshot guide for the Finish-Up-A-Thon post**

Use these suggested screenshots to illustrate the demo flow. Filenames below match the placeholders in `assets/screenshots/`.

- `assets/screenshots/dashboard.svg`
  - Purpose: hero image for the post. Show the control room overview: total entries, unique IPs/paths, top paths and threat board.
  - Tip: crop to 1200×630 for social preview; focus on the left part showing metrics.
  - Alt text: "MiddleMan Control Room dashboard showing top paths and threat board"

- `assets/screenshots/blocked.svg`
  - Purpose: show the containment behavior — a request blocked by a rule.
  - Tip: capture a browser with the dashboard open and trigger a blocked request (IP or path). Highlight the blocked line in the incident feed.
  - Alt text: "Blocked request detail showing rule and registry entry"

- `assets/screenshots/insights.svg`
  - Purpose: show the `/insights/` JSON that powers the dashboard; useful to demonstrate automation and reproducibility.
  - Tip: use a terminal or browser JSON viewer; crop to the JSON panel and keep the URL visible.
  - Alt text: "JSON insights endpoint returning summary statistics"

How to capture locally (macOS):

1. Start the app (use your usual command, e.g., `make run` or `python3 manage.py runserver`).
2. Open the dashboard at `http://localhost:8000/` and prepare the states (generate traffic, toggle a blacklist rule).
3. Use macOS screenshot utility to capture a selection:

```bash
# interactive selection
screencapture -i assets/screenshots/dashboard.png
# capture a window by clicking it
screencapture -w assets/screenshots/dashboard.png
```

4. Convert the generated PNG to optimized JPEG/PNG for the post if needed:

```bash
# convert and resize
sips -Z 1200 assets/screenshots/dashboard.png --out assets/screenshots/dashboard-1200.png
```

Replace the SVG placeholders with real screenshots before publishing.
