# Icons

These icon files are **generated, not committed**. This repository forbids raw NUL
bytes in tracked files (a text-only hygiene rule), so the binary PNG/ICO/ICNS files
Tauri needs are `.gitignore`d and must be produced locally before building.

Generate the placeholder set (a simple "heliopause ring" mark, no external deps):

```bash
python3 generate_icons.py
```

or replace them with a real logo at any time:

```bash
npx tauri icon path/to/logo.png
```

Either command writes the files `../tauri.conf.json` references:

- `32x32.png`, `128x128.png`, `128x128@2x.png` — PNG icons
- `icon.png` — 512x512 master PNG (also the default window icon)
- `icon.ico` — Windows
- `icon.icns` — macOS bundle

`generate_icons.py` is the only tracked file here besides this README; run it once
after cloning (or let a build script run it) so `tauri dev` / `tauri build` succeed.
