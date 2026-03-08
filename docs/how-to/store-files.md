# Store Files

This guide covers uploading, downloading, and deleting encrypted files (blobs).

## How blob encryption works

Every blob is encrypted with a randomly-generated **data encryption key (DEK)**. The DEK is returned to you when you upload and must be stored alongside the blob ID — the server never has it.

This is different from message and state encryption, where keys are derived from `symmetric_root`. Blob DEKs are ephemeral per-blob keys; you are responsible for storing them.

## Uploading a file

=== "Python"

    ```python
    from reeeductio import Space

    space = Space(
        space_id='S...',
        member_id='U...',
        private_key=...,
        symmetric_root=...,
        base_url='http://localhost:8000',
    )

    with open('report.pdf', 'rb') as f:
        data = f.read()

    result = space.encrypt_and_upload_blob(data)
    print('Blob ID:', result.blob_id)   # B...
    print('DEK (hex):', result.dek.hex())  # save this!
    ```

=== "TypeScript"

    ```typescript
    import { Space } from 'reeeductio';

    const space = new Space({ spaceId, keyPair, symmetricRoot, baseUrl: 'http://localhost:8000' });

    const data = new Uint8Array(await file.arrayBuffer());
    const result = await space.encryptAndUploadBlob(data);

    console.log('Blob ID:', result.blob_id);   // B...
    console.log('DEK (hex):', Buffer.from(result.key).toString('hex'));  // save this!
    ```

!!! warning "Save your DEK"
    Without the DEK you cannot decrypt the blob. Store it somewhere safe alongside the blob ID — for example, encrypted inside a message or in the space's State.

## Downloading and decrypting

=== "Python"

    ```python
    # Use the blob_id and DEK returned at upload time
    data = space.download_and_decrypt_blob(
        blob_id='B...',
        key=dek,   # the 32-byte DEK returned at upload
    )

    with open('report-copy.pdf', 'wb') as f:
        f.write(data)
    ```

=== "TypeScript"

    ```typescript
    const data = await space.downloadAndDecryptBlob(
      'B...',
      key,   // the Uint8Array DEK returned at upload
    );
    // data is a Uint8Array of the original file bytes
    ```

## Storing the DEK alongside the blob ID

The most common pattern is to post both the blob ID and the DEK as an encrypted message, so other authorized members can retrieve it:

=== "Python"

    ```python
    import json

    result = space.encrypt_and_upload_blob(data)

    # Store blob ID + DEK as an encrypted message
    payload = json.dumps({
        'blob_id': result.blob_id,
        'dek': result.dek.hex(),
        'filename': 'report.pdf',
        'content_type': 'application/pdf',
    }).encode()
    space.post_encrypted_message('files', 'file.upload', payload)
    ```

=== "TypeScript"

    ```typescript
    const result = await space.encryptAndUploadBlob(data);

    const payload = JSON.stringify({
      blob_id: result.blob_id,
      dek: Buffer.from(result.key).toString('hex'),
      filename: 'report.pdf',
      content_type: 'application/pdf',
    });
    await space.postEncryptedMessage('files', 'file.upload', stringToBytes(payload));
    ```

Recipients read the message, extract the blob ID and DEK, then download and decrypt:

=== "Python"

    ```python
    msgs = space.get_messages('files')
    for msg in msgs:
        meta = json.loads(space.decrypt_message_data(msg, 'files'))
        blob = space.download_and_decrypt_blob(
            blob_id=meta['blob_id'],
            key=bytes.fromhex(meta['dek']),
        )
        with open(meta['filename'], 'wb') as f:
            f.write(blob)
    ```

=== "TypeScript"

    ```typescript
    const { messages } = await space.getMessages('files');
    for (const msg of messages) {
      const meta = JSON.parse(bytesToString(space.decryptMessageData(msg, 'files')));
      const blob = await space.downloadAndDecryptBlob(
        meta.blob_id,
        Uint8Array.from(Buffer.from(meta.dek, 'hex')),
      );
      // blob is a Uint8Array of the file bytes
    }
    ```

## Deleting a blob

=== "Python"

    ```python
    space.delete_blob('B...')
    ```

=== "TypeScript"

    ```typescript
    await space.deleteBlob('B...');
    ```

!!! warning "Deletion is permanent"
    Once a blob is deleted, it cannot be recovered. Any messages containing the blob ID will have a broken reference.

## Uploading without encryption

If you need to store files that don't need to be encrypted (e.g. publicly readable assets), use the plaintext upload:

=== "Python"

    ```python
    result = space.upload_plaintext_blob(data)
    print('Blob ID:', result.blob_id)

    # Download (no key needed)
    data = space.download_plaintext_blob('B...')
    ```

=== "TypeScript"

    ```typescript
    import { uploadBlob, downloadBlob } from 'reeeductio';

    const token = await space.authenticate();
    const result = await uploadBlob(fetch, space.baseUrl, token, space.spaceId, data);
    const downloaded = await downloadBlob(fetch, space.baseUrl, token, space.spaceId, result.blob_id);
    ```

## Related

- [Blobs](../concepts/blobs.md) — concept overview
- [Send Messages](send-messages.md) — posting blob IDs as messages
- [Topics & Messages](../concepts/topics-and-messages.md)
