# Light Diary

A simple command-line diary tool written in Python.

## Features

- Markdown entries with YAML front matter
- Date tracking that persists through edits
- Inline input or system editor support
- Organized by year/month folders (`~/diary/2026/01/10.md`)

## Installation

```bash
git clone https://github.com/realwaynesun/diary-cli.git
cd diary-cli
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

Add an alias to your shell config (`~/.zshrc` or `~/.bashrc`):

```bash
alias diary="~/diary-cli/venv/bin/python ~/diary-cli/diary.py"
```

## Usage

```bash
# Add a new entry for today
diary add

# Add entry for a specific date
diary add --date 2026-01-15

# Quick shortcut for today (appends if exists)
diary today

# Use system editor instead of inline input
diary add --editor
diary today -e

# List all entries
diary list
diary list --year 2026
diary list --month 01

# View an entry
diary view 2026-01-10

# Edit an entry (preserves original date)
diary edit 2026-01-10

# Edit and change the date
diary edit 2026-01-10 --date 2026-01-12
```

## File Format

Entries are stored as markdown with YAML front matter:

```markdown
---
date: 2026-01-10
---

Your diary content here...
```

## Storage Location

Entries are stored in `~/diary/` organized by year and month:

```
~/diary/
├── 2026/
│   ├── 01/
│   │   ├── 10.md
│   │   └── 15.md
│   └── 02/
│       └── 01.md
```

## License

MIT
