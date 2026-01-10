# CLAUDE.md

This file provides context for Claude Code and other AI assistants working on this project.

## Project Overview

Light Diary is a single-file Python CLI tool for personal journaling. It prioritizes simplicity over features.

## Architecture

- `diary.py` - The entire application in one file
- Uses `click` for CLI parsing
- Entries stored as markdown with YAML front matter in `~/diary/YYYY/MM/DD.md`

## Key Design Decisions

1. **Date preservation**: When editing an entry, the original date in the front matter is preserved unless explicitly changed with `--date` flag
2. **Append behavior**: `diary today` appends to existing entries rather than overwriting
3. **No database**: Plain markdown files for portability and grep-ability
4. **Single file**: Entire app in `diary.py` to keep it "light"

## Commands

| Command | Description |
|---------|-------------|
| `add` | Create new entry (fails if exists) |
| `today` | Open/append to today's entry |
| `list` | List entries with optional filters |
| `view` | Display an entry |
| `edit` | Modify existing entry |

## Development

```bash
source venv/bin/activate
python diary.py --help
```

## Testing Changes

```bash
# Test with a specific date to avoid affecting real entries
python diary.py add --date 2099-12-31
python diary.py view 2099-12-31
python diary.py edit 2099-12-31
python diary.py list
```
