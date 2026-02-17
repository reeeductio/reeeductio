"""Role management commands."""

import click

from ...client import Space
from ..utils import handle_errors, parse_private_key


@click.group()
def role():
    """Manage roles in a space."""
    pass


@role.command("create")
@click.argument("role_name")
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
    "--description",
    "-d",
    default=None,
    help="Optional description of the role",
)
@click.pass_context
@handle_errors
def create_role(ctx, role_name: str, space_key: str, symmetric_root: str, description: str | None):
    """Create a role in the space.

    ROLE_NAME: Name of the role to create
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
        space.create_role(role_name, description=description)

    click.echo(f"Role created: {role_name}")
    click.echo(f"Space: {space_id}")


@role.command("grant")
@click.argument("role_name")
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
    "--cap-id",
    "-c",
    required=True,
    help="Capability ID",
)
@click.option(
    "--op",
    required=True,
    type=click.Choice(["read", "create", "modify", "delete", "write"]),
    help="Operation to grant",
)
@click.option(
    "--path",
    required=True,
    help="Resource path for the capability",
)
@click.pass_context
@handle_errors
def grant_to_role(ctx, role_name: str, space_key: str, symmetric_root: str, cap_id: str, op: str, path: str):
    """Grant a capability to a role.

    ROLE_NAME: Name of the role to grant the capability to
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
        space.grant_capability_to_role(role_name, cap_id, {"op": op, "path": path})

    click.echo(f"Capability granted to role {role_name}: {op} on {path}")
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
