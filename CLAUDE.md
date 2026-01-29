# CLAUDE.md

This file provides context for Claude Code and other AI assistants working on this project.

## Project Overview

Light Diary is a single-file Python CLI tool for personal journaling. It prioritizes simplicity over features.

## Architecture

- `diary.py` - The entire application in one file
- Uses `click` for CLI parsing
- Entries stored as markdown with YAML front matter in `~/diary/YYYY/MM/DD.md`
- Config stored in `~/.config/diary/config.yaml`

## Key Design Decisions

1. **Date preservation**: When editing an entry, the original date in the front matter is preserved unless explicitly changed with `--date` flag
2. **Append behavior**: `diary today` appends to existing entries rather than overwriting
3. **No database**: Plain markdown files for portability and grep-ability
4. **Single file**: Entire app in `diary.py` to keep it "light"
5. **Tags**: Support `@tag` syntax in entries, auto-extracted and stored in YAML front matter
6. **Multiple journals**: Support via config file, switch with `--journal` flag
7. **Encryption**: AES encryption with Fernet + PBKDF2HMAC for sensitive entries

## Commands

| Command | Description |
|---------|-------------|
| `add` | Create new entry (fails if exists), supports `--encrypted` |
| `today` | Open/append to today's entry |
| `list` | List entries with `--year`, `--month`, `--tag` filters |
| `view` | Display an entry |
| `edit` | Modify existing entry |
| `search` | Search entries by keyword with `--year`, `--month` filters |
| `tags` | List all tags with counts |
| `export` | Export entries as JSON, Markdown, or HTML |
| `journals` | List available journals |
| `encrypt` | Encrypt entry or all entries |
| `decrypt` | Decrypt entry or all entries |

## Global Options

| Option | Description |
|--------|-------------|
| `--journal`, `-j` | Select journal (from config) |

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

# Test new features
python diary.py search "keyword"
python diary.py tags
python diary.py export --format json
python diary.py journals
python diary.py encrypt 2099-12-31
python diary.py decrypt 2099-12-31
```

## Ticket Management

This project uses tk for task management. Run `tk help` for usage.

Common commands:
- `tk create "title" -t feature -p 1` - Create feature ticket
- `tk ls` - List open tickets
- `tk start <id>` - Start working on ticket
- `tk close <id>` - Close completed ticket
- `tk show <id>` - View ticket details

Tickets stored in `.tickets/` as markdown with YAML frontmatter.
