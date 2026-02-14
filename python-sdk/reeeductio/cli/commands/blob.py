"""Blob management commands."""

import click

from ...client import AdminClient
from ..utils import handle_errors, parse_private_key


@click.group()
def blob():
    """Manage blobs (admin operations)."""
    pass


@blob.command("delete")
@click.argument("blob_id")
@click.option(
    "--private-key",
    "-k",
    required=True,
    help="Admin private key in hex format",
)
@click.pass_context
@handle_errors
def delete(ctx, blob_id: str, private_key: str):
    """Delete a blob from server storage (admin only).

    BLOB_ID: The blob identifier (44-character base64 starting with 'B')
    """
    base_url = ctx.obj["base_url"]
    keypair = parse_private_key(private_key)

    with AdminClient(keypair, base_url=base_url) as admin:
        admin.delete_blob(blob_id)
        click.echo(f"Blob deleted: {blob_id}")
