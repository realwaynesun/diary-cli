#!/usr/bin/env python3
"""Light Diary - A simple CLI diary tool."""

import base64
import json
import os
import re
import sys
import subprocess
import tempfile
from datetime import datetime
from pathlib import Path
from typing import List, Optional

import click
import yaml
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# Configuration
CONFIG_DIR = Path.home() / ".config" / "diary"
CONFIG_FILE = CONFIG_DIR / "config.yaml"
DEFAULT_DIARY_DIR = Path.home() / "diary"
DATE_FORMAT = "%Y-%m-%d"

# Global state for current journal
_current_diary_dir: Optional[Path] = None


def load_config() -> dict:
    """Load configuration from config file."""
    if not CONFIG_FILE.exists():
        return {
            "default_journal": "personal",
            "journals": {
                "personal": str(DEFAULT_DIARY_DIR)
            }
        }

    try:
        with open(CONFIG_FILE) as f:
            config = yaml.safe_load(f)
            return config or {}
    except Exception:
        return {}


def save_config(config: dict) -> None:
    """Save configuration to config file."""
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    with open(CONFIG_FILE, "w") as f:
        yaml.dump(config, f, default_flow_style=False)


def get_journal_path(journal_name: str = None) -> Path:
    """Get path for a specific journal."""
    config = load_config()
    journals = config.get("journals", {"personal": str(DEFAULT_DIARY_DIR)})
    default_journal = config.get("default_journal", "personal")

    name = journal_name or default_journal

    if name not in journals:
        raise click.ClickException(f"Journal '{name}' not found. Available: {', '.join(journals.keys())}")

    return Path(journals[name]).expanduser()


def set_diary_dir(journal_name: str = None) -> None:
    """Set the current diary directory based on journal selection."""
    global _current_diary_dir
    _current_diary_dir = get_journal_path(journal_name)


def get_diary_path() -> Path:
    """Get the root diary directory path."""
    if _current_diary_dir:
        return _current_diary_dir
    return DEFAULT_DIARY_DIR


def get_entry_path(date: datetime, encrypted: bool = False) -> Path:
    """Get the file path for a specific date's entry."""
    diary_dir = get_diary_path()
    ext = ".enc.md" if encrypted else ".md"
    return diary_dir / str(date.year) / f"{date.month:02d}" / f"{date.day:02d}{ext}"


def derive_key(password: str, salt: bytes) -> bytes:
    """Derive encryption key from password using PBKDF2."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=480000,
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))


def encrypt_content(content: str, password: str) -> str:
    """Encrypt content with password."""
    salt = os.urandom(16)
    key = derive_key(password, salt)
    f = Fernet(key)
    encrypted = f.encrypt(content.encode())
    return base64.b64encode(salt + encrypted).decode()


def decrypt_content(encrypted_data: str, password: str) -> str:
    """Decrypt content with password."""
    raw = base64.b64decode(encrypted_data.encode())
    salt = raw[:16]
    encrypted = raw[16:]
    key = derive_key(password, salt)
    f = Fernet(key)
    return f.decrypt(encrypted).decode()


def parse_date(date_str: str) -> datetime:
    """Parse a date string (YYYY-MM-DD) to datetime."""
    try:
        return datetime.strptime(date_str, DATE_FORMAT)
    except ValueError:
        raise click.BadParameter(f"Invalid date format. Use YYYY-MM-DD (e.g., 2026-01-10)")


def extract_tags(content: str) -> List[str]:
    """Extract @tags from content."""
    return sorted(set(re.findall(r"@(\w+)", content)))


def read_entry(path: Path, password: str = None) -> tuple[datetime, str, List[str]]:
    """Read an entry file and return (date, content, tags)."""
    if not path.exists():
        raise click.ClickException(f"Entry not found: {path}")

    text = path.read_text()
    is_encrypted = path.suffix == ".md" and path.stem.endswith(".enc")

    if is_encrypted:
        if not password:
            password = click.prompt("Password", hide_input=True)
        try:
            text = decrypt_content(text.strip(), password)
        except Exception:
            raise click.ClickException("Failed to decrypt. Wrong password?")

    lines = text.split("\n")

    # Parse YAML front matter
    if lines[0].strip() == "---":
        end_idx = None
        for i, line in enumerate(lines[1:], 1):
            if line.strip() == "---":
                end_idx = i
                break

        if end_idx:
            date = None
            tags = []
            for line in lines[1:end_idx]:
                if line.startswith("date:"):
                    date_str = line.split(":", 1)[1].strip()
                    date = parse_date(date_str)
                elif line.startswith("tags:"):
                    tags_str = line.split(":", 1)[1].strip()
                    tags_str = tags_str.strip("[]")
                    if tags_str:
                        tags = [t.strip() for t in tags_str.split(",")]

            content = "\n".join(lines[end_idx + 1:]).strip()

            content_tags = extract_tags(content)
            all_tags = list(set(tags + content_tags))

            if date:
                return date, content, all_tags

    mtime = datetime.fromtimestamp(path.stat().st_mtime)
    content_tags = extract_tags(text)
    return mtime, text.strip(), content_tags


def write_entry(path: Path, date: datetime, content: str, tags: List[str] = None, password: str = None) -> None:
    """Write an entry with YAML front matter."""
    path.parent.mkdir(parents=True, exist_ok=True)

    content_tags = extract_tags(content)
    all_tags = list(set((tags or []) + content_tags))

    if all_tags:
        tags_str = ", ".join(sorted(all_tags))
        front_matter = f"---\ndate: {date.strftime(DATE_FORMAT)}\ntags: [{tags_str}]\n---\n\n"
    else:
        front_matter = f"---\ndate: {date.strftime(DATE_FORMAT)}\n---\n\n"

    full_content = front_matter + content

    if password:
        encrypted = encrypt_content(full_content, password)
        path.write_text(encrypted)
    else:
        path.write_text(full_content)


def get_content_from_editor(initial_content: str = "") -> str:
    """Open system editor and return the content."""
    editor = os.environ.get("EDITOR", "vim")

    with tempfile.NamedTemporaryFile(mode="w", suffix=".md", delete=False) as f:
        f.write(initial_content)
        temp_path = f.name

    try:
        subprocess.run([editor, temp_path], check=True)
        with open(temp_path) as f:
            return f.read().strip()
    finally:
        os.unlink(temp_path)


def get_content_inline() -> str:
    """Get content from inline input (stdin)."""
    click.echo("Enter your diary entry (Ctrl+D when done):")
    content = sys.stdin.read()
    return content.strip()


@click.group()
@click.version_option(version="1.0.0")
@click.option("--journal", "-j", default=None, help="Journal to use (default: from config)")
@click.pass_context
def cli(ctx, journal: str):
    """Light Diary - A simple CLI diary tool."""
    ctx.ensure_object(dict)
    set_diary_dir(journal)


@cli.command()
def journals():
    """List available journals."""
    config = load_config()
    journal_list = config.get("journals", {"personal": str(DEFAULT_DIARY_DIR)})
    default = config.get("default_journal", "personal")

    click.echo("Available journals:\n")
    for name, path in sorted(journal_list.items()):
        marker = " (default)" if name == default else ""
        click.echo(f"  {name}: {path}{marker}")


@cli.command()
@click.option("--date", "-d", "date_str", default=None, help="Date for the entry (YYYY-MM-DD)")
@click.option("--editor", "-e", is_flag=True, help="Open system editor instead of inline input")
@click.option("--encrypted", is_flag=True, help="Encrypt the entry")
def add(date_str: str, editor: bool, encrypted: bool):
    """Add a new diary entry."""
    if date_str:
        date = parse_date(date_str)
    else:
        date = datetime.now()

    entry_path = get_entry_path(date, encrypted=encrypted)
    plain_path = get_entry_path(date, encrypted=False)
    enc_path = get_entry_path(date, encrypted=True)

    if plain_path.exists() or enc_path.exists():
        raise click.ClickException(
            f"Entry already exists for {date.strftime(DATE_FORMAT)}. Use 'diary edit' to modify it."
        )

    password = None
    if encrypted:
        password = click.prompt("Password", hide_input=True)
        confirm = click.prompt("Confirm password", hide_input=True)
        if password != confirm:
            raise click.ClickException("Passwords do not match.")

    if editor:
        content = get_content_from_editor()
    else:
        content = get_content_inline()

    if not content:
        raise click.ClickException("Empty entry. Nothing saved.")

    write_entry(entry_path, date, content, password=password)
    click.echo(f"Entry saved: {entry_path}")


@cli.command()
@click.option("--editor", "-e", is_flag=True, help="Open system editor instead of inline input")
def today(editor: bool):
    """Open or create today's diary entry."""
    date = datetime.now()
    entry_path = get_entry_path(date)

    if entry_path.exists():
        # Edit existing entry
        existing_date, existing_content, existing_tags = read_entry(entry_path)

        if editor:
            content = get_content_from_editor(existing_content)
        else:
            click.echo(f"Current entry for {date.strftime(DATE_FORMAT)}:\n")
            click.echo(existing_content)
            click.echo("\n---")
            content = get_content_inline()
            if content:
                content = existing_content + "\n\n" + content
            else:
                content = existing_content

        write_entry(entry_path, existing_date, content, existing_tags)
        click.echo(f"Entry updated: {entry_path}")
    else:
        # Create new entry
        if editor:
            content = get_content_from_editor()
        else:
            content = get_content_inline()

        if not content:
            raise click.ClickException("Empty entry. Nothing saved.")

        write_entry(entry_path, date, content)
        click.echo(f"Entry saved: {entry_path}")


@cli.command(name="list")
@click.option("--month", "-m", default=None, help="Filter by month (YYYY-MM)")
@click.option("--year", "-y", default=None, help="Filter by year (YYYY)")
@click.option("--tag", "-t", default=None, help="Filter by tag")
def list_entries(month: str, year: str, tag: str):
    """List diary entries."""
    diary_path = get_diary_path()

    if not diary_path.exists():
        click.echo("No diary entries yet.")
        return

    entries = []

    for year_dir in sorted(diary_path.iterdir()):
        if not year_dir.is_dir():
            continue

        if year and year_dir.name != year:
            continue

        for month_dir in sorted(year_dir.iterdir()):
            if not month_dir.is_dir():
                continue

            if month:
                expected_month = month.split("-")[1] if "-" in month else month
                if month_dir.name != expected_month:
                    continue

            for entry_file in sorted(month_dir.glob("*.md")):
                if tag:
                    try:
                        _, _, entry_tags = read_entry(entry_file)
                        if tag not in entry_tags:
                            continue
                    except Exception:
                        continue

                entry_date = f"{year_dir.name}-{month_dir.name}-{entry_file.stem}"
                entries.append(entry_date)

    if not entries:
        click.echo("No entries found.")
        return

    click.echo(f"Found {len(entries)} entries:\n")
    for entry in entries:
        click.echo(f"  {entry}")


@cli.command()
@click.argument("date_str")
@click.option("--editor", "-e", is_flag=True, help="Open system editor instead of inline input")
@click.option("--date", "-d", "new_date_str", default=None, help="Change the entry date (YYYY-MM-DD)")
def edit(date_str: str, editor: bool, new_date_str: str):
    """Edit an existing diary entry."""
    date = parse_date(date_str)
    entry_path = get_entry_path(date)

    if not entry_path.exists():
        raise click.ClickException(f"No entry found for {date_str}")

    existing_date, existing_content, existing_tags = read_entry(entry_path)

    if editor:
        content = get_content_from_editor(existing_content)
    else:
        click.echo(f"Current content:\n")
        click.echo(existing_content)
        click.echo("\n---")
        click.echo("Enter new content (Ctrl+D when done), or Ctrl+C to cancel:")
        try:
            content = get_content_inline()
        except KeyboardInterrupt:
            click.echo("\nCancelled.")
            return

    if not content:
        raise click.ClickException("Empty entry. Nothing saved.")

    # Determine final date
    if new_date_str:
        final_date = parse_date(new_date_str)
    else:
        final_date = existing_date  # Preserve original date

    # If date changed, move the file
    if new_date_str and final_date != date:
        new_path = get_entry_path(final_date)
        if new_path.exists():
            raise click.ClickException(f"Entry already exists for {new_date_str}")

        write_entry(new_path, final_date, content, existing_tags)
        entry_path.unlink()
        click.echo(f"Entry moved and saved: {new_path}")
    else:
        write_entry(entry_path, final_date, content, existing_tags)
        click.echo(f"Entry updated: {entry_path}")


@cli.command()
@click.argument("date_str")
def view(date_str: str):
    """View a diary entry."""
    date = parse_date(date_str)
    entry_path = get_entry_path(date)

    if not entry_path.exists():
        raise click.ClickException(f"No entry found for {date_str}")

    entry_date, content, tags = read_entry(entry_path)

    click.echo(f"Date: {entry_date.strftime(DATE_FORMAT)}")
    if tags:
        click.echo(f"Tags: {', '.join(sorted(tags))}")
    click.echo()
    click.echo(content)


@cli.command()
@click.argument("keyword")
@click.option("--year", "-y", default=None, help="Filter by year (YYYY)")
@click.option("--month", "-m", default=None, help="Filter by month (YYYY-MM)")
def search(keyword: str, year: str, month: str):
    """Search entries for a keyword."""
    diary_path = get_diary_path()

    if not diary_path.exists():
        click.echo("No diary entries yet.")
        return

    keyword_lower = keyword.lower()
    matches = []

    for year_dir in sorted(diary_path.iterdir()):
        if not year_dir.is_dir():
            continue

        if year and year_dir.name != year:
            continue

        if month:
            month_year = month.split("-")[0] if "-" in month else None
            if month_year and year_dir.name != month_year:
                continue

        for month_dir in sorted(year_dir.iterdir()):
            if not month_dir.is_dir():
                continue

            if month:
                expected_month = month.split("-")[1] if "-" in month else month
                if month_dir.name != expected_month:
                    continue

            for entry_file in sorted(month_dir.glob("*.md")):
                try:
                    entry_date, content, _ = read_entry(entry_file)
                    if keyword_lower in content.lower():
                        matches.append((entry_date, content, entry_file))
                except Exception:
                    continue

    if not matches:
        click.echo(f"No entries found containing '{keyword}'")
        return

    click.echo(f"Found {len(matches)} entries containing '{keyword}':\n")

    for entry_date, content, entry_file in matches:
        click.echo(f"--- {entry_date.strftime(DATE_FORMAT)} ---")
        lines = content.split("\n")
        for line in lines:
            if keyword_lower in line.lower():
                highlighted = line.replace(
                    keyword, click.style(keyword, bold=True)
                ).replace(
                    keyword.lower(), click.style(keyword.lower(), bold=True)
                ).replace(
                    keyword.upper(), click.style(keyword.upper(), bold=True)
                ).replace(
                    keyword.capitalize(), click.style(keyword.capitalize(), bold=True)
                )
                click.echo(f"  {highlighted}")
        click.echo()


@cli.command()
def tags():
    """List all tags with counts."""
    diary_path = get_diary_path()

    if not diary_path.exists():
        click.echo("No diary entries yet.")
        return

    tag_counts = {}

    for year_dir in diary_path.iterdir():
        if not year_dir.is_dir():
            continue

        for month_dir in year_dir.iterdir():
            if not month_dir.is_dir():
                continue

            for entry_file in month_dir.glob("*.md"):
                try:
                    _, _, entry_tags = read_entry(entry_file)
                    for tag in entry_tags:
                        tag_counts[tag] = tag_counts.get(tag, 0) + 1
                except Exception:
                    continue

    if not tag_counts:
        click.echo("No tags found.")
        return

    click.echo(f"Found {len(tag_counts)} tags:\n")
    for tag in sorted(tag_counts.keys()):
        click.echo(f"  @{tag}: {tag_counts[tag]}")


def collect_entries(diary_path: Path) -> List[dict]:
    """Collect all entries as a list of dicts."""
    entries = []

    for year_dir in sorted(diary_path.iterdir()):
        if not year_dir.is_dir():
            continue

        for month_dir in sorted(year_dir.iterdir()):
            if not month_dir.is_dir():
                continue

            for entry_file in sorted(month_dir.glob("*.md")):
                try:
                    entry_date, content, entry_tags = read_entry(entry_file)
                    entries.append({
                        "date": entry_date.strftime(DATE_FORMAT),
                        "content": content,
                        "tags": sorted(entry_tags) if entry_tags else []
                    })
                except Exception:
                    continue

    return entries


def export_json(entries: List[dict]) -> str:
    """Export entries as JSON."""
    return json.dumps({"entries": entries}, indent=2, ensure_ascii=False)


def export_markdown(entries: List[dict]) -> str:
    """Export entries as concatenated Markdown."""
    parts = []
    for entry in entries:
        header = f"## {entry['date']}"
        if entry["tags"]:
            header += f" [{', '.join('@' + t for t in entry['tags'])}]"
        parts.append(header)
        parts.append("")
        parts.append(entry["content"])
        parts.append("")
    return "\n".join(parts)


def export_html(entries: List[dict]) -> str:
    """Export entries as HTML."""
    html_parts = [
        "<!DOCTYPE html>",
        "<html>",
        "<head>",
        "  <meta charset=\"utf-8\">",
        "  <title>Diary Export</title>",
        "  <style>",
        "    body { font-family: system-ui, sans-serif; max-width: 800px; margin: 2em auto; padding: 0 1em; }",
        "    .entry { margin-bottom: 2em; border-bottom: 1px solid #eee; padding-bottom: 1em; }",
        "    .date { font-size: 1.2em; font-weight: bold; color: #333; }",
        "    .tags { color: #666; font-size: 0.9em; margin-left: 1em; }",
        "    .content { margin-top: 0.5em; white-space: pre-wrap; }",
        "  </style>",
        "</head>",
        "<body>",
        "  <h1>Diary</h1>",
    ]

    for entry in entries:
        tags_html = ""
        if entry["tags"]:
            tags_html = f'<span class="tags">[{", ".join("@" + t for t in entry["tags"])}]</span>'

        content_escaped = (
            entry["content"]
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
        )

        html_parts.append(f'  <div class="entry">')
        html_parts.append(f'    <div class="date">{entry["date"]}{tags_html}</div>')
        html_parts.append(f'    <div class="content">{content_escaped}</div>')
        html_parts.append(f'  </div>')

    html_parts.extend(["</body>", "</html>"])
    return "\n".join(html_parts)


@cli.command()
@click.argument("date_str", required=False)
@click.option("--format", "-f", "fmt", type=click.Choice(["json", "markdown", "html"]), default="json", help="Export format")
def export(date_str: str, fmt: str):
    """Export entries in various formats."""
    diary_path = get_diary_path()

    if not diary_path.exists():
        click.echo("No diary entries yet.")
        return

    if date_str:
        date = parse_date(date_str)
        entry_path = get_entry_path(date)

        if not entry_path.exists():
            raise click.ClickException(f"No entry found for {date_str}")

        entry_date, content, entry_tags = read_entry(entry_path)
        entries = [{
            "date": entry_date.strftime(DATE_FORMAT),
            "content": content,
            "tags": sorted(entry_tags) if entry_tags else []
        }]
    else:
        entries = collect_entries(diary_path)

    if not entries:
        click.echo("No entries to export.")
        return

    if fmt == "json":
        click.echo(export_json(entries))
    elif fmt == "markdown":
        click.echo(export_markdown(entries))
    elif fmt == "html":
        click.echo(export_html(entries))


@cli.command()
@click.argument("date_str", required=False)
def encrypt(date_str: str):
    """Encrypt a diary entry or all entries."""
    diary_path = get_diary_path()

    if not diary_path.exists():
        click.echo("No diary entries yet.")
        return

    password = click.prompt("Password", hide_input=True)
    confirm = click.prompt("Confirm password", hide_input=True)

    if password != confirm:
        raise click.ClickException("Passwords do not match.")

    if date_str:
        date = parse_date(date_str)
        entry_path = get_entry_path(date)

        if not entry_path.exists():
            raise click.ClickException(f"No entry found for {date_str}")

        if entry_path.stem.endswith(".enc"):
            raise click.ClickException("Entry is already encrypted.")

        entry_date, content, tags = read_entry(entry_path)
        encrypted_path = get_entry_path(date, encrypted=True)
        write_entry(encrypted_path, entry_date, content, tags, password=password)
        entry_path.unlink()
        click.echo(f"Encrypted: {encrypted_path}")
    else:
        count = 0
        for year_dir in diary_path.iterdir():
            if not year_dir.is_dir():
                continue

            for month_dir in year_dir.iterdir():
                if not month_dir.is_dir():
                    continue

                for entry_file in month_dir.glob("*.md"):
                    if entry_file.stem.endswith(".enc"):
                        continue

                    try:
                        entry_date, content, tags = read_entry(entry_file)
                        encrypted_path = entry_file.with_name(entry_file.stem + ".enc.md")
                        write_entry(encrypted_path, entry_date, content, tags, password=password)
                        entry_file.unlink()
                        count += 1
                    except Exception as e:
                        click.echo(f"Failed to encrypt {entry_file}: {e}")

        click.echo(f"Encrypted {count} entries.")


@cli.command()
@click.argument("date_str", required=False)
def decrypt(date_str: str):
    """Decrypt a diary entry or all entries."""
    diary_path = get_diary_path()

    if not diary_path.exists():
        click.echo("No diary entries yet.")
        return

    password = click.prompt("Password", hide_input=True)

    if date_str:
        date = parse_date(date_str)
        encrypted_path = get_entry_path(date, encrypted=True)

        if not encrypted_path.exists():
            raise click.ClickException(f"No encrypted entry found for {date_str}")

        entry_date, content, tags = read_entry(encrypted_path, password=password)
        decrypted_path = get_entry_path(date)
        write_entry(decrypted_path, entry_date, content, tags)
        encrypted_path.unlink()
        click.echo(f"Decrypted: {decrypted_path}")
    else:
        count = 0
        for year_dir in diary_path.iterdir():
            if not year_dir.is_dir():
                continue

            for month_dir in year_dir.iterdir():
                if not month_dir.is_dir():
                    continue

                for entry_file in month_dir.glob("*.enc.md"):
                    try:
                        entry_date, content, tags = read_entry(entry_file, password=password)
                        decrypted_path = entry_file.with_name(entry_file.stem.replace(".enc", "") + ".md")
                        write_entry(decrypted_path, entry_date, content, tags)
                        entry_file.unlink()
                        count += 1
                    except Exception as e:
                        click.echo(f"Failed to decrypt {entry_file}: {e}")

        click.echo(f"Decrypted {count} entries.")


if __name__ == "__main__":
    cli()
