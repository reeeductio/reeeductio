"""Key generation and management commands."""

import json

import click

from ...crypto import generate_keypair, get_identifier_type
from ..utils import handle_errors


@click.group()
def key():
    """Key generation and management."""
    pass


@key.command("generate")
@click.option(
    "--output-format",
    type=click.Choice(["text", "json"]),
    default="text",
    help="Output format",
)
@handle_errors
def generate(output_format: str):
    """Generate a new Ed25519 keypair."""
    keypair = generate_keypair()

    result = {
        "private_key_hex": keypair.private_key.hex(),
        "public_key_hex": keypair.public_key.hex(),
        "user_id": keypair.to_user_id(),
        "space_id": keypair.to_space_id(),
        "tool_id": keypair.to_tool_id(),
    }

    if output_format == "json":
        click.echo(json.dumps(result, indent=2))
    else:
        click.echo("Generated new Ed25519 keypair:")
        click.echo("")
        click.echo(f"Private Key: {keypair.private_key.hex()}")
        click.echo(f"Public Key:  {keypair.public_key.hex()}")
        click.echo("")
        click.echo("Derived identifiers:")
        click.echo(f"  User ID:  {keypair.to_user_id()}")
        click.echo(f"  Space ID: {keypair.to_space_id()}")
        click.echo(f"  Tool ID:  {keypair.to_tool_id()}")


@key.command("info")
@click.argument("identifier")
@handle_errors
def key_info(identifier: str):
    """Display information about a typed identifier.

    IDENTIFIER: A 44-character typed identifier (User, Space, Tool, Message, or Blob)
    """
    try:
        id_type = get_identifier_type(identifier)
        click.echo(f"Type: {id_type}")
        click.echo(f"ID:   {identifier}")
    except ValueError as e:
        raise click.BadParameter(str(e))
