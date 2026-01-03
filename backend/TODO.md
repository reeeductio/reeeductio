1. ~~Refactor tests into smaller pieces, use a framework like pytest~~ ✓
2. ~~Rename the ...Manager classes to ...Store to better reflect what they do~~ ✓
3. ~~Create a MessageStore base class and SqlMessageStore, move current message storage from database.py into it~~ ✓
4. Create LmdbStateStore using LMDB
5. ~~Create a more generic SqlStateStore that can be a parent of SqliteStateStore, for future postgres or mysql support~~ ✓
6. ~~Create a more generic SqlMessageStore that can be a parent of SqliteMessageStore, for future postgres or mysql support~~ ✓
7. ~~Add support for websocket on /channel/{channel_id}/stream~~ ✓
8. ~~Add support for loading config from a file and/or environment variables~~ ✓
9. ~~Investigate adding caching for state and messages - look at functools, or write our own with a dictionary for easier manual update/invalidation~~ ✓
10. Add or integrate OPRF service - look at https://github.com/nthparty/oprf and https://github.com/nthparty/oprfs
11. Prep for running on AWS Lambda, Cloudflare Workers, Google serverless, etc
    - ~~Google Cloud Run / Firestore~~ ✓
12. ~~Create Dockerfile~~ ✓
13. ~~Think about moving each channel to use its own embedded databases~~  ✓
14. ~~Require SHA256 checksum on signed url uploads~~ ✓
15. ~~Add size limits for messages and blobs~~ ✓
16. Fix vulnerability in authz where we're not verifying the full signature chain back to the creator public key (URGENT)
17. Verify state signatures in the state store get_state() before adding to the cache, then we don't have to validate again and again in the Channel
18. Add an authz cache of public keys that we've already validated back to the creator key