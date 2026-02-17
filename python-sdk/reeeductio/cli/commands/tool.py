"""Tool management commands."""

import json
from datetime import datetime, timezone

import click

from ...client import Space
from ...crypto import get_identifier_type
from ..utils import handle_errors, parse_private_key


@click.group()
def tool():
    """Manage tools in a space."""
    pass


@tool.command("add")
@click.argument("tool_id")
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
def add_tool(ctx, tool_id: str, space_key: str, symmetric_root: str):
    """Add a tool to the space's authorization.

    TOOL_ID: The tool's 44-character identifier (starting with 'T')
    """
    base_url = ctx.obj["base_url"]

    # Validate tool_id format
    if len(tool_id) != 44:
        raise click.BadParameter(f"Tool ID must be 44 characters, got {len(tool_id)}")
    try:
        id_type = get_identifier_type(tool_id)
        if id_type != "TOOL":
            raise click.BadParameter(f"Expected TOOL identifier, got {id_type}")
    except ValueError as e:
        raise click.BadParameter(str(e))

    keypair = parse_private_key(space_key)
    sym_root = _parse_symmetric_root(symmetric_root)
    space_id = keypair.to_space_id()
    admin_user_id = keypair.to_user_id()

    # Create tool authorization data
    tool_data = json.dumps({
        "public_key": tool_id,
        "added_at": int(datetime.now(timezone.utc).timestamp() * 1000),
        "added_by": admin_user_id,
    })

    with Space(
        space_id=space_id,
        member_id=keypair.to_user_id(),
        private_key=keypair.private_key,
        symmetric_root=sym_root,
        base_url=base_url,
    ) as space:
        space.set_plaintext_state(f"auth/tools/{tool_id}", tool_data)

    click.echo(f"Tool added: {tool_id}")
    click.echo(f"Space: {space_id}")


@tool.command("remove")
@click.argument("tool_id")
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
def remove_tool(ctx, tool_id: str, space_key: str, symmetric_root: str):
    """Remove a tool from the space's authorization.

    TOOL_ID: The tool's 44-character identifier (starting with 'T')
    """
    base_url = ctx.obj["base_url"]

    # Validate tool_id format
    if len(tool_id) != 44:
        raise click.BadParameter(f"Tool ID must be 44 characters, got {len(tool_id)}")

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
        # Remove by setting empty state
        space.set_plaintext_state(f"auth/tools/{tool_id}", "")

    click.echo(f"Tool removed: {tool_id}")
    click.echo(f"Space: {space_id}")


@tool.command("list")
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
def list_tools(ctx, space_key: str, symmetric_root: str, output_format: str):
    """List tools in the space (via state history)."""
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
        # Get state history and filter for auth/tools/ paths
        history = space.get_state_history()
        tools = {}
        for msg in history:
            if msg.type.startswith("auth/tools/"):
                tid = msg.type.replace("auth/tools/", "")
                # Track the latest state for each tool
                if msg.data:
                    tools[tid] = msg.data
                else:
                    # Empty data means removed
                    tools.pop(tid, None)

    if output_format == "json":
        click.echo(json.dumps({"tools": list(tools.keys())}, indent=2))
    else:
        if tools:
            click.echo(f"Tools in space {space_id}:")
            for tid in tools:
                click.echo(f"  {tid}")
        else:
            click.echo(f"No tools found in space {space_id}")


@tool.command("grant")
@click.argument("tool_id")
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
def grant_tool(ctx, tool_id: str, space_key: str, symmetric_root: str, cap_id: str, op: str, path: str):
    """Grant a capability to a tool.

    TOOL_ID: The tool's 44-character identifier (starting with 'T')
    """
    base_url = ctx.obj["base_url"]

    if len(tool_id) != 44:
        raise click.BadParameter(f"Tool ID must be 44 characters, got {len(tool_id)}")
    try:
        id_type = get_identifier_type(tool_id)
        if id_type != "TOOL":
            raise click.BadParameter(f"Expected TOOL identifier, got {id_type}")
    except ValueError as e:
        raise click.BadParameter(str(e))

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
        space.grant_capability_to_tool(tool_id, cap_id, {"op": op, "path": path})

    click.echo(f"Capability granted to tool {tool_id}: {op} on {path}")
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
