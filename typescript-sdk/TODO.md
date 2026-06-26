1. ~~Add support for new OPAQUE endpoints~~
2. ~~Set up workflow for publishing to npm~~
3. ~~Add user symmetric key~~
   - Optional 32-byte `userSymmetricKey` constructor param (length-validated)
   - Derive `userMessageKey` / `userDataKey` via HKDF, domain-separated by `spaceId`
   - Build this like the Python and Swift SDKs: make the generic encrypted get/set
     functions take an optional key that defaults to the appropriate space key, then
     implement the user functions by calling the generic ones with the user key
   - `getEncryptedUserData` / `setEncryptedUserData` for `user/{memberId}/{path}`
     (confidential against other space members and the server)
4. Make symmetric keys optional, for admin tools (also TODO in the Python SDK)
5. ~~Add `createInvitation`~~
   — create invitation tool
   - grant `can_create_user` + `can_grant_user_role` (see Python `create_invitation`)
6. Add `createSpace` on the admin client — register a new space in the admin space
   (derive space_id, write registration with space_signature, index under the user)
7. Finish WebSocket streaming — currently only the URL helpers and
   `handleIncomingMessage` exist; add a real stream iterator that yields parsed and
   verified messages (see Python `connect` / `stream` / `stream_messages`)
8. Consider a CLI to match the Python SDK (auth, blob, key, opaque, role, space,
   tool, user commands)
