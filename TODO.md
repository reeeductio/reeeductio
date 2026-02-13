1. ~~Per-topic message encryption keys, so we could provide some users with limited access to only certain topics~~ ✓
2. ~~Change "channel" to "queue"^H^H^Hspace everywhere to emphasize the "encrypted pubsub" approach, and to sound less like a Telegram/Signal/Matrix/IRC competitor~~ ✓
3. ~~Role-based access control.  Add state under roles/{role_name}/rights/ with the rights for that role.~~ ✓
4. ~~Figure out a plan for /create/channel/{channel_id} or /channels/{channel_id}/create and an /admin API~~ ✓
5. ~~Figure out a plan for /login~~ ✓
6. ~~Add spec for websocket on /channel/{channel_id}/stream~~ ✓
7. ~~Separate keys into "tools" and "users", where users inherit the "user" role by default but tools have only their specific rights~~ ✓
8. ~~Add "self" wildcard for paths~~ ✓
9. ~~Python client library~~ ✓
10. ~~TypeScript client library~~ ✓
11. Allow "@" character in paths, to enable email addresses as usernames in the login program
12. ~~High level client SDKs should have `setEncryptedState()` and `setPlaintextState()` but no ambiguous `setState()` function so it's always super clear what you're exposing to the server~~ ✓
13. Clean up README and other docs for human consumption
14. Rename "new" Python sdk to just python-sdk
15. Add developer docs with hints on how to build a chat app or a forum etc
16. Add developer docs for setting up the backend server
17. Submit opaque_snake and python-sdk to pypi
18. Submit typescript-sdk to npm
19. Submit backend container image to docker.org