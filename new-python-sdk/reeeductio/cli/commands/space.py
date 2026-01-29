"""Space management commands."""

import json
import os

import click

from ...crypto import generate_keypair
from ..utils import handle_errors, parse_private_key


@click.group()
def space():
    """Manage spaces."""
    pass


@space.command("create")
@click.option(
    "--output-format",
    type=click.Choice(["text", "json"]),
    default="text",
    help="Output format for credentials",
)
@handle_errors
def create(output_format: str):
    """Generate a new space keypair and display credentials.

    Creates a new Ed25519 keypair and derives the space ID.
    Outputs the private key (hex), public key, and space ID.
    """
    keypair = generate_keypair()
    space_id = keypair.to_space_id()
    user_id = keypair.to_user_id()

    # Generate a random symmetric root for the space
    symmetric_root = os.urandom(32)

    result = {
        "space_id": space_id,
        "user_id": user_id,
        "private_key_hex": keypair.private_key.hex(),
        "public_key_hex": keypair.public_key.hex(),
        "symmetric_root_hex": symmetric_root.hex(),
    }

    if output_format == "json":
        click.echo(json.dumps(result, indent=2))
    else:
        click.echo("Space created successfully!")
        click.echo("")
        click.echo(f"Space ID:        {space_id}")
        click.echo(f"User ID:         {user_id}")
        click.echo(f"Private Key:     {keypair.private_key.hex()}")
        click.echo(f"Symmetric Root:  {symmetric_root.hex()}")
        click.echo("")
        click.echo("IMPORTANT: Save these credentials securely. The private key cannot be recovered.")


@space.command("info")
@click.option(
    "--private-key",
    "-k",
    required=True,
    help="Private key in hex format (64 characters)",
)
@handle_errors
def info(private_key: str):
    """Display space information from a private key."""
    keypair = parse_private_key(private_key)

    click.echo(f"Space ID:  {keypair.to_space_id()}")
    click.echo(f"User ID:   {keypair.to_user_id()}")
    click.echo(f"Tool ID:   {keypair.to_tool_id()}")
