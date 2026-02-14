"""User management commands."""

import json
from datetime import datetime, timezone

import click

from ...client import Space
from ...crypto import get_identifier_type
from ..utils import handle_errors, parse_private_key


@click.group()
def user():
    """Manage users in a space."""
    pass


@user.command("add")
@click.argument("user_id")
@click.option(
    "--space-key",
    "-k",
    required=True,
    help="Space owner's private key in hex format",
)
@click.option(
    "--symmetric-root",
    "-s",
    required=True,
    help="Space's symmetric root key in hex format",
)
@click.pass_context
@handle_errors
def add_user(ctx, user_id: str, space_key: str, symmetric_root: str):
    """Add a user to the space's authorization.

    USER_ID: The user's 44-character identifier (starting with 'U')
    """
    base_url = ctx.obj["base_url"]

    # Validate user_id format
    if len(user_id) != 44:
        raise click.BadParameter(f"User ID must be 44 characters, got {len(user_id)}")
    try:
        id_type = get_identifier_type(user_id)
        if id_type != "USER":
            raise click.BadParameter(f"Expected USER identifier, got {id_type}")
    except ValueError as e:
        raise click.BadParameter(str(e))

    keypair = parse_private_key(space_key)
    sym_root = _parse_symmetric_root(symmetric_root)
    space_id = keypair.to_space_id()
    admin_user_id = keypair.to_user_id()

    # Create member data
    member_data = json.dumps({
        "public_key": user_id,
        "added_at": int(datetime.now(timezone.utc).timestamp() * 1000),
        "added_by": admin_user_id,
    })

    with Space(
        space_id=space_id,
        keypair=keypair,
        symmetric_root=sym_root,
        base_url=base_url,
    ) as space:
        space.set_plaintext_state(f"auth/users/{user_id}", member_data)

    click.echo(f"User added: {user_id}")
    click.echo(f"Space: {space_id}")


@user.command("remove")
@click.argument("user_id")
@click.option(
    "--space-key",
    "-k",
    required=True,
    help="Space owner's private key in hex format",
)
@click.option(
    "--symmetric-root",
    "-s",
    required=True,
    help="Space's symmetric root key in hex format",
)
@click.pass_context
@handle_errors
def remove_user(ctx, user_id: str, space_key: str, symmetric_root: str):
    """Remove a user from the space's authorization.

    USER_ID: The user's 44-character identifier (starting with 'U')
    """
    base_url = ctx.obj["base_url"]

    # Validate user_id format
    if len(user_id) != 44:
        raise click.BadParameter(f"User ID must be 44 characters, got {len(user_id)}")

    keypair = parse_private_key(space_key)
    sym_root = _parse_symmetric_root(symmetric_root)
    space_id = keypair.to_space_id()

    with Space(
        space_id=space_id,
        keypair=keypair,
        symmetric_root=sym_root,
        base_url=base_url,
    ) as space:
        # Remove by setting empty state (or could use a "deleted" marker)
        space.set_plaintext_state(f"auth/users/{user_id}", "")

    click.echo(f"User removed: {user_id}")
    click.echo(f"Space: {space_id}")


@user.command("list")
@click.option(
    "--space-key",
    "-k",
    required=True,
    help="Space owner's private key in hex format",
)
@click.option(
    "--symmetric-root",
    "-s",
    required=True,
    help="Space's symmetric root key in hex format",
)
@click.option(
    "--output-format",
    type=click.Choice(["text", "json"]),
    default="text",
    help="Output format",
)
@click.pass_context
@handle_errors
def list_users(ctx, space_key: str, symmetric_root: str, output_format: str):
    """List users in the space (via state history)."""
    base_url = ctx.obj["base_url"]

    keypair = parse_private_key(space_key)
    sym_root = _parse_symmetric_root(symmetric_root)
    space_id = keypair.to_space_id()

    with Space(
        space_id=space_id,
        keypair=keypair,
        symmetric_root=sym_root,
        base_url=base_url,
    ) as space:
        # Get state history and filter for auth/users/ paths
        history = space.get_state_history()
        users = {}
        for msg in history:
            if msg.type.startswith("auth/users/"):
                user_id = msg.type.replace("auth/users/", "")
                # Track the latest state for each user
                if msg.data:
                    users[user_id] = msg.data
                else:
                    # Empty data means removed
                    users.pop(user_id, None)

    if output_format == "json":
        click.echo(json.dumps({"users": list(users.keys())}, indent=2))
    else:
        if users:
            click.echo(f"Users in space {space_id}:")
            for uid in users:
                click.echo(f"  {uid}")
        else:
            click.echo(f"No users found in space {space_id}")


def _parse_symmetric_root(symmetric_root_hex: str) -> bytes:
    """Parse a hex-encoded symmetric root key."""
    try:
        if len(symmetric_root_hex) != 64:
            raise click.BadParameter(
                f"Symmetric root must be 64 hex characters (32 bytes), got {len(symmetric_root_hex)}"
            )
        return bytes.fromhex(symmetric_root_hex)
    except ValueError as e:
        raise click.BadParameter(f"Invalid hex format for symmetric root: {e}")
