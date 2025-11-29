# SinDiff

**The fastest, cleanest, most reliable binary & patch diffing plugin for IDA Pro 9.x**

Tired of waiting 10+ minutes for Diaphora?  
SinDiff finds patched functions in **seconds** — no bloat, no crashes, no nonsense.

### Features
- Lightning fast (pure assembly + optional pseudocode hashing)
- Smart heuristics (detects added checks, memset, removed strcpy, etc.)
- Double-click any result → instantly jumps to function
- Works with or without Hex-Rays decompiler
- Zero console spam, zero crashes
- Hotkey: **Alt+Shift+S**

### Installation
1. Copy `SinDiff.py` → `C:\Program Files\IDA Professional 9.2\plugins\`
2. Restart IDA
3. Press **Alt+Shift+S** → type `export` → save `.db`
4. Load patched binary → repeat export
5. → type `diff` → select both files → profit

### Screenshot
![SinDiff in action](screenshots/results.png)

### Made with love by Sinn
Star if you hunt 1-days
