"""Main CLI entry point."""

import click

from .commands import auth, blob, key, space


@click.group()
@click.version_option(package_name="reeeductio-client")
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


if __name__ == "__main__":
    cli()
