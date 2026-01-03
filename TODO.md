1. Per-topic message encryption keys, so we could provide some users with limited access to only certain topics.  topic_key = HKDF(symmetric_root, topic_id)
2. Change "channel" to "queue" everywhere to emphasize the "encrypted pubsub" approach, and to sound less like a Telegram/Signal/Matrix/IRC competitor
3. ~~Role-based access control.  Add state under roles/{role_name}/rights/ with the rights for that role.~~ ✓
4. Figure out a plan for /create/channel/{channel_id} or /channels/{channel_id}/create and an /admin API
   - Request needs to be signed by some trusted key, which must be loaded from config or some database.
   - Maybe config has a master public key that defines an admin channel/queue that contains all the other authorizations ???
5. Figure out a plan for /login
   - Maybe this uses a special queue too, with public key given in the config
6. ~~Add spec for websocket on /channel/{channel_id}/stream~~ ✓
7. ~~Separate keys into "tools" and "users", where users inherit the "user" role by default but tools have only their specific rights~~ ✓
8. ~~Add "self" wildcard for paths~~ ✓
9. Python client library
10. Javascript client library - Can we build automatically from the OpenAPI spec?