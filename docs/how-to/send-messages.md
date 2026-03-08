# Send Messages

This guide covers sending and receiving encrypted messages, working with multiple topics, and subscribing to real-time updates.

## Basic send and receive

Messages are encrypted client-side before sending. The server stores only ciphertext.

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

    # Send
    result = space.post_encrypted_message(
        topic_id='general',
        msg_type='chat.text',
        data=b'Hello, encrypted world!',
    )
    print('Posted:', result.message_hash)

    # Receive
    msgs = space.get_messages('general')
    for msg in msgs:
        text = space.decrypt_message_data(msg, 'general')
        print(f'[{msg.message_hash[:12]}] {text.decode()}')
    ```

=== "TypeScript"

    ```typescript
    import { Space, stringToBytes, bytesToString } from 'reeeductio';

    const space = new Space({ spaceId, keyPair, symmetricRoot, baseUrl: 'http://localhost:8000' });

    // Send
    const result = await space.postEncryptedMessage('general', 'chat.text', stringToBytes('Hello!'));
    console.log('Posted:', result.message_hash);

    // Receive
    const { messages } = await space.getMessages('general');
    for (const msg of messages) {
      console.log(`[${msg.message_hash.slice(0, 12)}] ${bytesToString(space.decryptMessageData(msg, 'general'))}`);
    }
    ```

## Message types

The `msg_type` / `type` field is a free-form string you define. Use it to distinguish different kinds of events in a topic:

| Type | Meaning |
|------|---------|
| `chat.text` | Plain text message |
| `chat.image` | Image (data is a blob ID) |
| `event.join` | User joined the space |
| `event.leave` | User left |
| `file.upload` | File uploaded (data is a blob ID) |

=== "Python"

    ```python
    import json

    # Post a structured JSON message
    payload = json.dumps({'text': 'Hello!', 'mentions': ['U...']}).encode()
    space.post_encrypted_message('general', 'chat.text', payload)
    ```

=== "TypeScript"

    ```typescript
    const payload = JSON.stringify({ text: 'Hello!', mentions: ['U...'] });
    await space.postEncryptedMessage('general', 'chat.text', stringToBytes(payload));
    ```

## Working with multiple topics

Topics are independent — create as many as you like. Topic IDs must be lowercase alphanumeric + hyphens or underscores, 2–64 characters.

=== "Python"

    ```python
    space.post_encrypted_message('general', 'chat.text', b'Hi everyone')
    space.post_encrypted_message('engineering', 'chat.text', b'Deploy complete')
    space.post_encrypted_message('announcements', 'event.announcement', b'New release!')
    ```

=== "TypeScript"

    ```typescript
    await space.postEncryptedMessage('general', 'chat.text', stringToBytes('Hi everyone'));
    await space.postEncryptedMessage('engineering', 'chat.text', stringToBytes('Deploy complete'));
    await space.postEncryptedMessage('announcements', 'event.announcement', stringToBytes('New release!'));
    ```

## Querying messages

Filter messages by time range or limit the count:

=== "Python"

    ```python
    import time

    # Last hour
    one_hour_ago = int(time.time() * 1000) - 3_600_000
    recent = space.get_messages('general', from_timestamp=one_hour_ago)

    # Most recent 10 messages (reverse-chronological)
    latest = space.get_messages(
        'general',
        from_timestamp=9999999999999,
        to_timestamp=0,
        limit=10,
    )
    ```

=== "TypeScript"

    ```typescript
    const oneHourAgo = Date.now() - 3_600_000;
    const { messages: recent } = await space.getMessages('general', { from: oneHourAgo });

    // Most recent 10
    const { messages: latest } = await space.getMessages('general', {
      from: Date.now(),
      to: 0,
      limit: 10,
    });
    ```

## Verifying the message chain

By default, the SDK verifies that `prev_hash` links are intact on every fetch. If the chain is broken, a `ChainError` is raised. You can also validate explicitly:

=== "Python"

    ```python
    from reeeductio.messages import validate_message_chain

    msgs = space.get_messages('general')
    valid = validate_message_chain(space.space_id, msgs)
    print('Chain valid:', valid)
    ```

=== "TypeScript"

    ```typescript
    import { validateMessageChainWithAnchor } from 'reeeductio';

    const { messages } = await space.getMessages('general');
    const valid = validateMessageChainWithAnchor(space.spaceId, messages, null);
    console.log('Chain valid:', valid);
    ```

## Real-time updates (WebSocket)

Subscribe to a topic to receive new messages as they arrive:

=== "Python"

    ```python
    import asyncio
    from reeeductio import Space

    async def listen():
        space = Space(...)
        async with space.subscribe('general') as stream:
            async for msg in stream:
                text = space.decrypt_message_data(msg, 'general')
                print(f'New message: {text.decode()}')

    asyncio.run(listen())
    ```

=== "TypeScript"

    ```typescript
    // WebSocket support coming soon — use polling in the meantime:
    setInterval(async () => {
      const { messages } = await space.getMessages('general', { from: lastSeen });
      for (const msg of messages) {
        console.log(bytesToString(space.decryptMessageData(msg, 'general')));
        lastSeen = msg.server_timestamp;
      }
    }, 1000);
    ```

## Attaching files

For large payloads, upload a blob and include its ID in the message:

=== "Python"

    ```python
    # Upload the file
    with open('photo.jpg', 'rb') as f:
        result = space.encrypt_and_upload_blob(f.read())

    # Post a reference message
    import json
    payload = json.dumps({'blob_id': result.blob_id, 'filename': 'photo.jpg'}).encode()
    space.post_encrypted_message('photos', 'chat.image', payload)
    ```

=== "TypeScript"

    ```typescript
    const data = new Uint8Array(await file.arrayBuffer());
    const { blob_id, key } = await space.encryptAndUploadBlob(data);

    const payload = JSON.stringify({ blob_id, filename: file.name });
    await space.postEncryptedMessage('photos', 'chat.image', stringToBytes(payload));
    ```

## Related

- [Store Files](store-files.md) — uploading and downloading blob attachments
- [Topics & Messages](../concepts/topics-and-messages.md) — concept overview
- [Access Control](../concepts/access-control.md) — controlling who can post
