"""Space management commands."""

import json
import os

import click

from ...client import Space, AdminSpace
from ...crypto import generate_keypair
from ..utils import handle_errors, parse_private_key


@click.group()
def space():
    """Manage spaces."""
    pass


@space.command("create")
@click.option(
    "--private-key",
    "-k",
    required=True,
    help="Private key for the new space owner (hex format). If not provided, generates a new one.",
)
@click.option(
    "--symmetric-root",
    "-s",
    required=False,
    help="Symmetric root key for the new space (hex format). If not provided, generates a new one.",
)
@click.option(
    "--output-format",
    type=click.Choice(["text", "json"]),
    default="text",
    help="Output format for credentials",
)
@click.pass_context
@handle_errors
def create(ctx, private_key: str, symmetric_root: str|None, output_format: str):
    """Create a new space on the server.

    Generates credentials (if not provided), connects to the server,
    and creates the space by authenticating to it.
    """
    base_url = ctx.obj["base_url"]

    # Parse or generate keypair
    admin_keypair = parse_private_key(private_key)
    sym_root = _parse_symmetric_root(symmetric_root)

    admin_space_id = admin_keypair.to_space_id()
    admin_user_id = admin_keypair.to_user_id()

    # Create the admin space by authenticating to it (backend auto-creates on first auth)
    with AdminSpace(
        space_id=admin_space_id,
        keypair=admin_keypair,
        symmetric_root=sym_root,
        base_url=base_url,
    ) as a:
        # Authenticate to trigger space creation
        a.authenticate()

        # Generate keypair for new space
        new_space_keypair = generate_keypair()

        # Register the space in the admin space
        new_space_id = a.create_space(new_space_keypair)

        # Generate a symmetric root for the new space
        new_sym_root = os.urandom(32)

        result = {
            "space_id": new_space_id,
            "private_key_hex": new_space_keypair.private_key.hex(),
            "public_key_hex": new_space_keypair.public_key.hex(),
            "symmetric_root_hex": sym_root.hex(),
            "base_url": base_url,
        }

        if output_format == "json":
            click.echo(json.dumps(result, indent=2))
        else:
            click.echo("Space created successfully!")
            click.echo("")
            click.echo(f"Space ID:        {new_space_id}")
            click.echo(f"Private Key:     {new_space_keypair.private_key.hex()}")
            click.echo(f"Symmetric Root:  {new_sym_root.hex()}")
            click.echo(f"Server:          {base_url}")
            click.echo("")
            click.echo("IMPORTANT: Save these credentials securely. The private key cannot be recovered.")


@space.command("generate")
@click.option(
    "--output-format",
    type=click.Choice(["text", "json"]),
    default="text",
    help="Output format for credentials",
)
@handle_errors
def generate(output_format: str):
    """Generate new space credentials locally (without creating on server).

    Creates a new Ed25519 keypair and symmetric root.
    Use 'space create' to actually create the space on the server.
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
        click.echo("Generated new space credentials:")
        click.echo("")
        click.echo(f"Space ID:        {space_id}")
        click.echo(f"User ID:         {user_id}")
        click.echo(f"Private Key:     {keypair.private_key.hex()}")
        click.echo(f"Symmetric Root:  {symmetric_root.hex()}")
        click.echo("")
        click.echo("Use 'reeeductio-admin space create' to create this space on a server.")


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


def _parse_symmetric_root(symmetric_root_hex: str | None) -> bytes:
    """Parse a hex-encoded symmetric root key, or generate one if not provided."""
    if symmetric_root_hex is None:
        return os.urandom(32)

    try:
        if len(symmetric_root_hex) != 64:
            raise click.BadParameter(
                f"Symmetric root must be 64 hex characters (32 bytes), got {len(symmetric_root_hex)}"
            )
        return bytes.fromhex(symmetric_root_hex)
    except ValueError as e:
        raise click.BadParameter(f"Invalid hex format for symmetric root: {e}")
