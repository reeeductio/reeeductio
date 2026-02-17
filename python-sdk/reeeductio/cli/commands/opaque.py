"""OPAQUE password authentication commands."""

import click

from ...client import Space
from ..utils import handle_errors, parse_private_key


@click.group()
def opaque():
    """Manage OPAQUE password authentication."""
    pass


@opaque.command("enable")
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
def enable(ctx, space_key: str, symmetric_root: str):
    """Enable OPAQUE password authentication for the space.

    This is an admin-only operation that:
    1. Creates the OPAQUE server setup (stored in data)
    2. Creates the opaque-user role (stored in state)
    3. Adds the CREATE capability for opaque user registration

    Must be run before any users can register with OPAQUE.
    """
    base_url = ctx.obj["base_url"]

    keypair = parse_private_key(space_key)
    sym_root = _parse_symmetric_root(symmetric_root)
    space_id = keypair.to_space_id()

    with Space(
        space_id=space_id,
        member_id=keypair.to_user_id(),
        private_key=keypair.private_key,
        symmetric_root=sym_root,
        base_url=base_url,
    ) as space:
        result = space.enable_opaque()

    click.echo(f"OPAQUE enabled for space {space_id}")
    if result["server_setup_created"]:
        click.echo("  Server setup: created")
    else:
        click.echo("  Server setup: already existed")
    if result["role_created"]:
        click.echo("  Opaque-user role: created")
    else:
        click.echo("  Opaque-user role: already existed")
    if result["capability_created"]:
        click.echo("  Registration capability: created")
    else:
        click.echo("  Registration capability: already existed")


@opaque.command("register")
@click.option(
    "--space-key",
    "-k",
    required=True,
    help="User's private key in hex format",
)
@click.option(
    "--symmetric-root",
    "-s",
    required=True,
    help="Space's symmetric root key in hex format",
)
@click.option(
    "--username",
    "-n",
    required=True,
    help="OPAQUE username (must be unique within the space)",
)
@click.option(
    "--password",
    "-p",
    default=None,
    help="Password for OPAQUE login (will prompt securely if not provided)",
)
@click.pass_context
@handle_errors
def register(ctx, space_key: str, symmetric_root: str, username: str, password: str | None):
    """Register OPAQUE credentials for a user.

    Creates password-based login credentials so the user can later
    recover their keypair and symmetric root by logging in with
    username and password.

    OPAQUE must be enabled for the space first (see 'opaque enable').
    """
    base_url = ctx.obj["base_url"]

    if password is None:
        password = click.prompt("Password", hide_input=True, confirmation_prompt=True)

    keypair = parse_private_key(space_key)
    sym_root = _parse_symmetric_root(symmetric_root)
    space_id = keypair.to_space_id()

    with Space(
        space_id=space_id,
        member_id=keypair.to_user_id(),
        private_key=keypair.private_key,
        symmetric_root=sym_root,
        base_url=base_url,
    ) as space:
        registered_username = space.opaque_register(username, password)

    click.echo(f"OPAQUE credentials registered for user: {registered_username}")
    click.echo(f"Space: {space_id}")


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
