"""Authentication test commands."""

import click

from ...client import AdminClient
from ..utils import handle_errors, parse_private_key


@click.group()
def auth():
    """Authentication operations."""
    pass


@auth.command("test")
@click.option(
    "--private-key",
    "-k",
    required=True,
    help="Admin private key in hex format",
)
@click.pass_context
@handle_errors
def test_auth(ctx, private_key: str):
    """Test admin authentication against the server."""
    base_url = ctx.obj["base_url"]
    keypair = parse_private_key(private_key)

    click.echo(f"Testing authentication to {base_url}...")

    with AdminClient(keypair, base_url=base_url, auto_authenticate=False) as admin:
        admin.authenticate()
        space_id = admin.get_space_id()

        click.echo("Authentication successful!")
        click.echo(f"Admin Space ID: {space_id}")
