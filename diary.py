#!/usr/bin/env python3
"""Light Diary - A simple CLI diary tool."""

import os
import sys
import subprocess
import tempfile
from datetime import datetime
from pathlib import Path

import click

# Configuration
DIARY_DIR = Path.home() / "diary"
DATE_FORMAT = "%Y-%m-%d"


def get_diary_path() -> Path:
    """Get the root diary directory path."""
    return DIARY_DIR


def get_entry_path(date: datetime) -> Path:
    """Get the file path for a specific date's entry."""
    return DIARY_DIR / str(date.year) / f"{date.month:02d}" / f"{date.day:02d}.md"


def parse_date(date_str: str) -> datetime:
    """Parse a date string (YYYY-MM-DD) to datetime."""
    try:
        return datetime.strptime(date_str, DATE_FORMAT)
    except ValueError:
        raise click.BadParameter(f"Invalid date format. Use YYYY-MM-DD (e.g., 2026-01-10)")


def read_entry(path: Path) -> tuple[datetime, str]:
    """Read an entry file and return (date, content)."""
    if not path.exists():
        raise click.ClickException(f"Entry not found: {path}")

    text = path.read_text()
    lines = text.split("\n")

    # Parse YAML front matter
    if lines[0].strip() == "---":
        end_idx = None
        for i, line in enumerate(lines[1:], 1):
            if line.strip() == "---":
                end_idx = i
                break

        if end_idx:
            # Extract date from front matter
            date = None
            for line in lines[1:end_idx]:
                if line.startswith("date:"):
                    date_str = line.split(":", 1)[1].strip()
                    date = parse_date(date_str)
                    break

            content = "\n".join(lines[end_idx + 1:]).strip()
            if date:
                return date, content

    # Fallback: use file modification time
    mtime = datetime.fromtimestamp(path.stat().st_mtime)
    return mtime, text.strip()


def write_entry(path: Path, date: datetime, content: str) -> None:
    """Write an entry with YAML front matter."""
    path.parent.mkdir(parents=True, exist_ok=True)

    front_matter = f"---\ndate: {date.strftime(DATE_FORMAT)}\n---\n\n"
    path.write_text(front_matter + content)


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
def cli():
    """Light Diary - A simple CLI diary tool."""
    pass


@cli.command()
@click.option("--date", "-d", "date_str", default=None, help="Date for the entry (YYYY-MM-DD)")
@click.option("--editor", "-e", is_flag=True, help="Open system editor instead of inline input")
def add(date_str: str, editor: bool):
    """Add a new diary entry."""
    if date_str:
        date = parse_date(date_str)
    else:
        date = datetime.now()

    entry_path = get_entry_path(date)

    if entry_path.exists():
        raise click.ClickException(
            f"Entry already exists for {date.strftime(DATE_FORMAT)}. Use 'diary edit' to modify it."
        )

    if editor:
        content = get_content_from_editor()
    else:
        content = get_content_inline()

    if not content:
        raise click.ClickException("Empty entry. Nothing saved.")

    write_entry(entry_path, date, content)
    click.echo(f"Entry saved: {entry_path}")


@cli.command()
@click.option("--editor", "-e", is_flag=True, help="Open system editor instead of inline input")
def today(editor: bool):
    """Open or create today's diary entry."""
    date = datetime.now()
    entry_path = get_entry_path(date)

    if entry_path.exists():
        # Edit existing entry
        existing_date, existing_content = read_entry(entry_path)

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

        write_entry(entry_path, existing_date, content)
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


@cli.command()
@click.option("--month", "-m", default=None, help="Filter by month (YYYY-MM)")
@click.option("--year", "-y", default=None, help="Filter by year (YYYY)")
def list(month: str, year: str):
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

    existing_date, existing_content = read_entry(entry_path)

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

        write_entry(new_path, final_date, content)
        entry_path.unlink()
        click.echo(f"Entry moved and saved: {new_path}")
    else:
        write_entry(entry_path, final_date, content)
        click.echo(f"Entry updated: {entry_path}")


@cli.command()
@click.argument("date_str")
def view(date_str: str):
    """View a diary entry."""
    date = parse_date(date_str)
    entry_path = get_entry_path(date)

    if not entry_path.exists():
        raise click.ClickException(f"No entry found for {date_str}")

    entry_date, content = read_entry(entry_path)

    click.echo(f"Date: {entry_date.strftime(DATE_FORMAT)}\n")
    click.echo(content)


if __name__ == "__main__":
    cli()
