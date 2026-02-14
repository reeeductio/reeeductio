"""Main CLI entry point."""

import click

from .commands import auth, blob, key, space, tool, user


def _get_version() -> str:
    """Get package version, with fallback for development installs."""
    try:
        from importlib.metadata import version
        return version("reeeductio-client")
    except Exception:
        return "dev"


@click.group()
@click.version_option(version=_get_version())
@click.option(
    "--base-url",
    "-u",
    default="http://localhost:8000",
    help="Base URL of the reeeductio server",
)
@click.option(
    "--output",
    "-o",
    type=click.Choice(["text", "json"]),
    default="text",
    help="Output format",
)
@click.pass_context
def cli(ctx, base_url: str, output: str):
    """Reeeductio admin CLI for space management."""
    ctx.ensure_object(dict)
    ctx.obj["base_url"] = base_url
    ctx.obj["output"] = output


# Register command groups
cli.add_command(space.space)
cli.add_command(key.key)
cli.add_command(blob.blob)
cli.add_command(auth.auth)
cli.add_command(user.user)
cli.add_command(tool.tool)


if __name__ == "__main__":
    cli()
