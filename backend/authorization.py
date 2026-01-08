"""
Authorization engine for capability-based access control

Implements:
- Capability loading and verification
- Path pattern matching with wildcards
- Permission checking (read/create/modify/delete/write)
- Capability subset validation (prevent privilege escalation)
- Ownership-restricted capabilities

Operations:
- read: Read-only access
- create: Write access, but only if object does NOT already exist
- modify: Write access, but only if object ALREADY exists
- delete: Delete access (remove existing objects)
- write: Full write access (dominates create, modify, and delete)

Ownership Restriction:
- Capabilities can include an optional "must_be_owner": true flag
- When must_be_owner=true, the capability only applies to objects created by the user
  (where signed_by matches the user's ID)
- For create operations, must_be_owner flag is ignored (you'll own what you create)
- For other operations, ownership is verified via lazy state entry lookup
- Ownership creates a second dimension in the capability lattice:
  * must_be_owner=false (unrestricted) dominates must_be_owner=true (ownership-restricted)
"""

from typing import Optional, List, Dict, Any
from data_store import DataStore
from crypto import CryptoUtils
from identifiers import extract_public_key, decode_identifier, IdType
from path_validation import validate_capability_path, PathValidationError
import fnmatch
import base64
import json
import time


class AuthorizationEngine:
    """Capability-based authorization with signed permissions"""

    def __init__(self, state_store: DataStore, crypto: CryptoUtils):
        self.state_store = state_store
        self.crypto = crypto
        # Cache for validated public key chains: (space_id, member_id) -> bool
        # This avoids re-walking the chain on every operation
        self._chain_validation_cache: Dict[tuple, bool] = {}

    def _is_tool(self, identifier: str) -> bool:
        """Check if an identifier is a tool (has 'T' type prefix)"""
        try:
            tid = decode_identifier(identifier)
            return tid.id_type == IdType.TOOL
        except Exception:
            return False

    def _verify_state_entry_signature(
        self,
        space_id: str,
        state_entry: Dict[str, Any]
    ) -> bool:
        """
        Verify the signature on a state entry.

        All state entries must be cryptographically signed. This verifies that
        the state entry's signature is valid.

        Args:
            space_id: Space identifier
            state_entry: State entry dict with path, data, signature, signed_by, signed_at

        Returns:
            True if signature is valid
        """
        required_fields = ["path", "data", "signature", "signed_by", "signed_at"]
        if not all(field in state_entry for field in required_fields):
            return False

        try:
            # Reconstruct the message that was signed: space_id|path|data|signed_at
            message_to_sign = '|'.join([
                space_id,
                state_entry["path"],
                state_entry["data"],
                str(state_entry["signed_at"])
            ]).encode('utf-8')

            signature_bytes = self.crypto.base64_decode(state_entry["signature"])
            signer_public_key = extract_public_key(state_entry["signed_by"])

            return self.crypto.verify_signature(message_to_sign, signature_bytes, signer_public_key)
        except Exception as e:
            print(f"State entry signature verification failed: {e}")
            return False

    def check_permission(
        self,
        space_id: str,
        member_id: str,
        operation: str,
        state_path: str
    ) -> bool:
        """
        Check if user or tool has permission for an operation on a state path

        Supports ownership-restricted capabilities with lazy state entry loading.
        State entry is only loaded when a matching capability has must_be_owner=true.

        Args:
            space_id: Space identifier
            member_id: User or tool typed identifier
            operation: 'read', 'create', 'modify', 'delete', or 'write'
            state_path: State path being accessed

        Returns:
            True if user/tool has permission
        """
        # Tools have NO ambient authority - they can only use explicit capabilities
        if self._is_tool(member_id):
            # Load tool capabilities only
            capabilities = self._load_tool_capabilities(space_id, member_id)

            # Check if any capability grants permission (with ownership check)
            for cap in capabilities:
                if self._check_capability_with_ownership(
                    cap, operation, state_path, member_id, space_id
                ):
                    return True

            return False

        # For users: Space creator has god mode
        # Compare underlying public keys (space and user IDs have different type prefixes)
        try:
            space_pubkey = extract_public_key(space_id)
            user_pubkey = extract_public_key(member_id)
            if space_pubkey == user_pubkey:
                return True
        except ValueError:
            # If extraction fails, fall through to capability check
            pass

        # Load direct capabilities for this user
        capabilities = self._load_user_capabilities(space_id, member_id)
        print(f"Found {len(capabilities)} capabilities for user {member_id}")

        # Load capabilities inherited from roles
        role_capabilities = self._load_role_capabilities(space_id, member_id)
        print(f"Found {len(role_capabilities)} capabilities for user {member_id}")

        # Combine all capabilities
        all_capabilities = capabilities + role_capabilities

        # Check if any capability grants permission (with ownership check)
        for cap in all_capabilities:
            if self._check_capability_with_ownership(
                cap, operation, state_path, member_id, space_id
            ):
                return True

        return False

    def _check_capability_with_ownership(
        self,
        capability: dict,
        operation: str,
        state_path: str,
        member_id: str,
        space_id: str
    ) -> bool:
        """
        Check if a capability grants permission, with lazy ownership verification.

        This method:
        1. First checks path and operation (cheap)
        2. Only if those match AND must_be_owner=true, loads state entry (expensive)
        3. Verifies ownership by comparing signed_by field

        Args:
            capability: Capability dict with 'op', 'path', and optional 'must_be_owner'
            operation: Operation being performed
            state_path: State path being accessed
            member_id: User or tool identifier
            space_id: Space identifier (for state lookup)

        Returns:
            True if capability grants permission
        """
        # First check path and operation (cheap)
        if not self._capability_grants_permission(capability, operation, state_path, member_id):
            return False

        # Path and operation match! Now check ownership if needed
        must_be_owner = capability.get("must_be_owner", False)

        if not must_be_owner:
            # Non-ownership-restricted capability grants access immediately
            return True

        # Ownership-restricted capability - need to verify ownership
        # Special case: create operations are always allowed
        # (you'll become the owner when you create it)
        if operation == "create":
            return True

        # For other operations, verify ownership via state entry lookup
        # This is the lazy loading - only happens when needed
        state_entry = self.state_store.get_state(space_id, state_path)

        if not state_entry:
            # No entry exists, so you can't own it
            return False

        # Check if member owns this entry
        return state_entry.get("signed_by") == member_id
    
    def _load_user_capabilities(
        self,
        space_id: str,
        user_id: str
    ) -> List[Dict[str, Any]]:
        """
        Load all capabilities for a user from state

        Capabilities are stored at state path:
        auth/users/{public_key}/rights/{capability_id}

        Data is base64-encoded JSON, so we need to decode it.

        SECURITY: Also verifies the chain of trust for the user to prevent
        database tampering attacks.
        """
        # CRITICAL: Verify user has valid chain of trust back to space admin
        # This prevents an attacker from inserting a user directly into the database
        if not self.verify_chain_of_trust(space_id, user_id):
            print(f"User {user_id} has invalid chain of trust - rejecting all capabilities")
            return []

        prefix = f"auth/users/{user_id}/rights"
        capability_states = self.state_store.list_state(space_id, prefix)
        print(f"Found {len(capability_states)} rights state entries for user {user_id}")

        capabilities = []
        for state in capability_states:
            # Verify state entry signature first
            if not self._verify_state_entry_signature(space_id, state):
                print(f"Invalid state entry signature for {state.get('path', 'unknown')}")
                continue

            # SECURITY: Verify the signer has a valid chain of trust
            signed_by = state.get("signed_by")
            if signed_by and not self.verify_chain_of_trust(space_id, signed_by):
                print(f"Capability at {state.get('path')} signed by untrusted key {signed_by}")
                continue

            # Decode base64 data and parse JSON
            try:
                decoded = base64.b64decode(state["data"])
                cap = json.loads(decoded)
                capabilities.append(cap)
            except Exception as e:
                # Skip invalid capability entries
                print(f"Failed to decode capability: {e}")
                continue

        return capabilities

    def _load_role_capabilities(
        self,
        space_id: str,
        user_id: str
    ) -> List[Dict[str, Any]]:
        """
        Load all capabilities inherited from user's roles.

        Process:
        1. Load user's role memberships from auth/users/{user_id}/roles/
        2. For each role, load role's capabilities from auth/roles/{role_id}/rights/
        3. Verify all capability signatures and chain of trust
        4. Return combined list of all role capabilities

        Args:
            space_id: Space identifier
            user_id: User's typed identifier

        Returns:
            List of capability dictionaries from all roles

        SECURITY: Verifies chain of trust for user and all signers to prevent
        database tampering attacks.
        """
        # CRITICAL: Verify user has valid chain of trust back to space admin
        if not self.verify_chain_of_trust(space_id, user_id):
            print(f"User {user_id} has invalid chain of trust - rejecting all role capabilities")
            return []

        # Load user's role grants
        role_prefix = f"auth/users/{user_id}/roles/"
        role_grants = self.state_store.list_state(space_id, role_prefix)

        all_role_capabilities = []

        for role_grant_state in role_grants:
            # Verify role grant state entry signature first
            if not self._verify_state_entry_signature(space_id, role_grant_state):
                print(f"Invalid state entry signature for role grant {role_grant_state.get('path', 'unknown')}")
                continue

            # SECURITY: Verify the role grant signer has a valid chain of trust
            signed_by = role_grant_state.get("signed_by")
            if signed_by and not self.verify_chain_of_trust(space_id, signed_by):
                print(f"Role grant at {role_grant_state.get('path')} signed by untrusted key {signed_by}")
                continue

            try:
                # Decode role grant
                decoded = base64.b64decode(role_grant_state["data"])
                role_grant = json.loads(decoded)

                role_id = role_grant.get("role_id")
                if not role_id:
                    continue

                # Check if role grant has expired
                expires_at = role_grant.get("expires_at")
                if expires_at and expires_at < (int(time.time() * 1000)):
                    continue  # Skip expired role

                # Load capabilities for this role
                role_cap_prefix = f"auth/roles/{role_id}/rights/"
                role_cap_states = self.state_store.list_state(space_id, role_cap_prefix)

                for cap_state in role_cap_states:
                    # Verify role capability state entry signature
                    if not self._verify_state_entry_signature(space_id, cap_state):
                        print(f"Invalid state entry signature for role capability {cap_state.get('path', 'unknown')}")
                        continue

                    # SECURITY: Verify the capability signer has a valid chain of trust
                    cap_signed_by = cap_state.get("signed_by")
                    if cap_signed_by and not self.verify_chain_of_trust(space_id, cap_signed_by):
                        print(f"Role capability at {cap_state.get('path')} signed by untrusted key {cap_signed_by}")
                        continue

                    try:
                        cap_decoded = base64.b64decode(cap_state["data"])
                        cap = json.loads(cap_decoded)
                        all_role_capabilities.append(cap)
                    except Exception as e:
                        print(f"Failed to decode role capability: {e}")
                        continue

            except Exception as e:
                print(f"Failed to decode role grant: {e}")
                continue

        return all_role_capabilities

    def _load_tool_capabilities(
        self,
        space_id: str,
        tool_public_key: str
    ) -> List[Dict[str, Any]]:
        """
        Load all capabilities for a tool from state.

        Tools have NO ambient authority - they can ONLY use capabilities
        explicitly granted in auth/tools/{tool_id}/rights/

        Args:
            space_id: Space identifier
            tool_public_key: Tool's typed identifier

        Returns:
            List of capability dictionaries

        SECURITY: Verifies chain of trust for tool and all signers to prevent
        database tampering attacks.
        """
        # CRITICAL: Verify tool has valid chain of trust back to space admin
        if not self.verify_chain_of_trust(space_id, tool_public_key):
            print(f"Tool {tool_public_key} has invalid chain of trust - rejecting all capabilities")
            return []

        prefix = f"auth/tools/{tool_public_key}/rights/"
        capability_states = self.state_store.list_state(space_id, prefix)

        capabilities = []
        for state in capability_states:
            # Verify state entry signature first
            if not self._verify_state_entry_signature(space_id, state):
                print(f"Invalid state entry signature for tool capability {state.get('path', 'unknown')}")
                continue

            # SECURITY: Verify the signer has a valid chain of trust
            signed_by = state.get("signed_by")
            if signed_by and not self.verify_chain_of_trust(space_id, signed_by):
                print(f"Tool capability at {state.get('path')} signed by untrusted key {signed_by}")
                continue

            try:
                decoded = base64.b64decode(state["data"])
                cap = json.loads(decoded)
                capabilities.append(cap)
            except Exception as e:
                print(f"Failed to decode tool capability: {e}")
                continue

        return capabilities

    def _capability_grants_permission(
        self,
        capability: dict,
        operation: str,
        state_path: str,
        user_public_key: Optional[str] = None
    ) -> bool:
        """
        Check if a capability grants permission for an operation on a path

        Args:
            capability: Capability dict with 'op' and 'path'
            operation: 'read', 'create', 'modify', 'delete', or 'write'
            state_path: State path being accessed
            user_public_key: User's public key for {self} wildcard resolution

        Returns:
            True if capability grants permission
        """
        cap_op = capability["op"]
        cap_path = capability["path"]

        # Check if path matches
        if not self._path_matches(cap_path, state_path, user_public_key):
            return False

        # Check if operation is allowed
        # Operation hierarchy:
        # - write dominates all operations (create, modify, delete, read)
        # - create, modify, and delete are independent of each other
        # - read is independent
        if cap_op == "write":
            # write grants read, create, modify, delete, and write
            return operation in ["read", "create", "modify", "delete", "write"]
        elif cap_op == "create":
            # create only grants create (write to non-existing objects)
            return operation == "create"
        elif cap_op == "modify":
            # modify only grants modify (write to existing objects)
            return operation == "modify"
        elif cap_op == "delete":
            # delete only grants delete (remove existing objects)
            return operation == "delete"
        elif cap_op == "read":
            return operation == "read"

        return False
    
    def _path_matches(self, pattern: str, path: str, user_public_key: Optional[str] = None) -> bool:
        """
        Check if a path matches a pattern with wildcards

        Patterns:
        - {any} matches one path segment
        - {self} resolves to user_public_key
        - {other} matches any segment except user_public_key
        - {...} matches any remaining path segments (rest wildcard, any depth)
        - Trailing '/' indicates prefix match (deprecated - use {...} instead)

        Examples:
          pattern="members/{any}", path="members/alice", user="U_alice" → True
          pattern="profiles/{self}/", path="profiles/U_alice/settings", user="U_alice" → True
          pattern="auth/users/{any}", path="auth/users/U_alice" → True
          pattern="auth/users/{any}", path="auth/users/U_alice/roles/admin" → False
          pattern="auth/users/{...}", path="auth/users/U_alice/roles/admin" → True
          pattern="auth/users/{any}/{...}", path="auth/users/U_alice/roles/admin" → True

        Args:
            pattern: Pattern with optional wildcards
            path: Path to match
            user_public_key: User's public key for {self} wildcard resolution

        Returns:
            True if path matches pattern
        """
        # Normalize paths - remove leading/trailing slashes
        pattern = pattern.strip('/')
        path = path.strip('/')

        # Handle empty pattern (matches everything)
        if pattern == '':
            return True

        # Split into segments
        pattern_parts = pattern.split('/')
        path_parts = path.split('/')

        # Check for {...} rest wildcard - if present, it must be the last segment
        has_rest_wildcard = len(pattern_parts) > 0 and pattern_parts[-1] == '{...}'

        if has_rest_wildcard:
            # Remove {...} from pattern for segment matching
            pattern_parts = pattern_parts[:-1]
            # Pattern (without {...}) cannot have more segments than path
            if len(pattern_parts) > len(path_parts):
                return False
        else:
            # Without {...}, pattern cannot have more segments than path
            if len(pattern_parts) > len(path_parts):
                return False

        # Check each segment in the pattern
        for i, pattern_part in enumerate(pattern_parts):
            if pattern_part == '{any}':
                # {any} wildcard matches any single segment
                continue
            elif pattern_part == '{self}':
                # {self} resolves to user's public key
                if user_public_key is None:
                    # Cannot match {self} without user context
                    return False
                if path_parts[i] != user_public_key:
                    return False
            elif pattern_part == '{other}':
                # {other} matches any segment EXCEPT user's public key
                if user_public_key is not None and path_parts[i] == user_public_key:
                    return False
                # Otherwise matches
                continue
            elif pattern_part != path_parts[i]:
                # Literal segment must match exactly
                return False

        # All pattern segments matched
        # If we have {...}, we match regardless of remaining path segments
        if has_rest_wildcard:
            return True

        # Without {...}, we need exact depth match
        return len(pattern_parts) == len(path_parts)
    
    def is_capability_path(self, path: str) -> bool:
        """
        Check if a state path is for capability grants

        Capability paths:
        - auth/users/{public_key}/rights/{capability_id}
        - auth/roles/{role_id}/rights/{capability_id}
        - auth/tools/{tool_id}/rights/{capability_id}
        """
        parts = path.strip('/').split('/')
        return (
            len(parts) >= 5 and
            parts[0] == 'auth' and
            parts[1] in ('users', 'roles', 'tools') and
            parts[3] == 'rights'
        )

    def is_role_grant_path(self, path: str) -> bool:
        """
        Check if a state path is for role grants

        Role grant paths: auth/users/{public_key}/roles/{role_id}
        """
        parts = path.strip('/').split('/')
        return (
            len(parts) >= 5 and
            parts[0] == 'auth' and
            parts[1] == 'users' and
            parts[3] == 'roles'
        )

    def is_tool_definition_path(self, path: str) -> bool:
        """
        Check if a state path is for a tool definition

        Tool definition paths: auth/tools/{tool_id}
        """
        parts = path.strip('/').split('/')
        return (
            len(parts) == 3 and
            parts[0] == 'auth' and
            parts[1] == 'tools'
        )
    
    def verify_capability_grant(
        self,
        space_id: str,
        path: str,
        capability_data: dict,
        granted_by: str
    ) -> bool:
        """
        Verify that a capability grant is valid

        Checks:
        1. Capability path pattern is valid (no unknown wildcards)
        2. For users (not tools): Granter has the capability they're trying to grant (superset check)
        3. For tools: They can write any capability for which they have write permission

        Note: The state entry signature is verified separately by the caller.
        This method only validates the capability grant logic.

        Args:
            space_id: Typed space identifier
            path: State path where capability is being stored
            capability_data: The capability being granted
            granted_by: Typed user identifier or tool identifier of the writer

        Returns:
            True if grant is valid
        """
        print("Authz: Verifying capability grant")
        print(f"Space = {space_id}")

        # Validate the capability path pattern
        capability_path = capability_data.get("path", "")
        try:
            validate_capability_path(capability_path)
        except PathValidationError as e:
            print(f"Invalid capability path pattern '{capability_path}': {e}")
            return False
        print("Capability path validates")

        # Extract recipient public key from path
        # Path format:
        # - auth/users/{subject_id}/rights/{cap_id}
        # - auth/tools/{subject_id}/rights/{cap_id}
        parts = path.strip('/').split('/')
        if len(parts) < 3:
            print(f"Not enough parts: {path}")
            return False

        subject_id = parts[2]
        print(f"Found subject: {subject_id}")

        # Space creator can grant anything
        try:
            if extract_public_key(granted_by) == extract_public_key(space_id):
                return True
        except Exception:
            return False

        # Tools can write any capability for which they have write permission
        # No superset check needed for tools - they just need the write capability
        if self._is_tool(granted_by):
            print(f"Granter {granted_by} is a tool - skipping superset check")
            return True

        # For users: verify they have superset of the capability they're granting
        # Load granter's capabilities
        granter_caps = self._load_user_capabilities(space_id, granted_by)

        # Check if granter has permission to grant capabilities
        can_grant = False
        for cap in granter_caps:
            if self._capability_grants_permission(
                cap,
                "create",
                "auth/users/{any}/rights/",
                granted_by
            ):
                can_grant = True
                break

        if not can_grant:
            print(f"Grantor {granted_by} can't grant capability")
            return False

        # Check if granter has the capability they're trying to grant (subset check)
        has_superset = self._has_capability_superset(
            granter_caps,
            [capability_data]
        )

        if not has_superset:
            print(f"Grantor {granted_by} lacks privileges of the requested capability")

        return has_superset

    def verify_role_grant(
        self,
        space_id: str,
        path: str,
        role_grant_data: dict,
        granted_by: str
    ) -> bool:
        """
        Verify that a role grant is valid

        Checks:
        1. Granter exists (or is space_id)
        2. Role exists
        3. Granter has superset of all capabilities in the role

        Note: The state entry signature is verified separately by the caller.
        This method only validates the role grant logic.

        Args:
            space_id: Typed space identifier
            path: State path where role grant is being stored
            role_grant_data: The role grant being created
            granted_by: Typed user identifier of granter

        Returns:
            True if grant is valid
        """
        # Extract recipient and role from path
        # Path format: auth/users/{recipient_key}/roles/{role_id}
        parts = path.strip('/').split('/')
        if len(parts) < 5:
            return False

        role_id = parts[4]

        # Space creator can grant anything
        # Compare the underlying public keys (granter might be U_xxx while space is C_xxx)
        try:
            if extract_public_key(granted_by) == extract_public_key(space_id):
                return True
        except Exception:
            return False

        # Load all capabilities in this role
        role_cap_prefix = f"auth/roles/{role_id}/rights/"
        role_cap_states = self.state_store.list_state(space_id, role_cap_prefix)

        role_capabilities = []
        for cap_state in role_cap_states:
            # Verify state entry signature first
            if not self._verify_state_entry_signature(space_id, cap_state):
                print(f"Invalid state entry signature for role capability {cap_state.get('path', 'unknown')}")
                continue

            try:
                cap_decoded = base64.b64decode(cap_state["data"])
                cap = json.loads(cap_decoded)
                role_capabilities.append(cap)
            except Exception as e:
                print(f"Failed to decode role capability: {e}")
                continue

        # If role has no capabilities, allow grant
        if not role_capabilities:
            return True

        # Load granter's capabilities (including their roles!)
        granter_direct_caps = self._load_user_capabilities(space_id, granted_by)
        granter_role_caps = self._load_role_capabilities(space_id, granted_by)
        granter_all_caps = granter_direct_caps + granter_role_caps

        # Check if granter has permission to grant roles
        can_grant_roles = False
        for cap in granter_all_caps:
            if self._capability_grants_permission(
                cap,
                "create",
                "auth/users/{any}/roles/",
                granted_by
            ):
                can_grant_roles = True
                break

        if not can_grant_roles:
            return False

        # Check if granter has superset of all role capabilities
        return self._has_capability_superset(
            granter_all_caps,
            role_capabilities
        )

    def _has_capability_superset(
        self,
        granter_caps: List[dict],
        requested_caps: List[dict]
    ) -> bool:
        """
        Check if granter has a superset of the requested capabilities

        This prevents privilege escalation - you can't grant what you don't have.

        Two-dimensional capability lattice:
        1. Operation hierarchy:
           - write dominates everything (create, modify, delete, read)
           - create, modify, and delete are independent (none dominates the others)
           - read is independent
        2. Ownership hierarchy:
           - must_be_owner=false (unrestricted) dominates must_be_owner=true (restricted)

        A granter capability covers a requested capability if it dominates in BOTH dimensions:
        - Operation must be equal or stronger
        - Ownership restriction must be equal or weaker (less restrictive)

        Args:
            granter_caps: Capabilities the granter has
            requested_caps: Capabilities being requested

        Returns:
            True if granter has all requested capabilities (or stronger)
        """
        for req_cap in requested_caps:
            req_op = req_cap["op"]
            req_path = req_cap["path"]
            req_must_be_owner = req_cap.get("must_be_owner", False)

            # Check if granter has matching or stronger capability
            has_capability = False

            for grant_cap in granter_caps:
                grant_op = grant_cap["op"]
                grant_path = grant_cap["path"]
                grant_must_be_owner = grant_cap.get("must_be_owner", False)

                # Path must match or be a superset
                # grant_path="/state/*" covers req_path="/state/members/"
                if not self._path_covers(grant_path, req_path):
                    continue

                # Operation must be equal or stronger
                op_dominates = False
                if grant_op == "write":
                    # write covers everything (create, modify, delete, read)
                    op_dominates = True
                elif grant_op == req_op:
                    # Same operation
                    op_dominates = True
                # else: different ops, neither dominates (create/modify/delete/read are independent)

                if not op_dominates:
                    continue

                # Ownership restriction must be equal or weaker (less restrictive)
                # must_be_owner=false (unrestricted) dominates must_be_owner=true (restricted)
                # In other words: grant_must_be_owner <= req_must_be_owner
                # (false=0 <= true=1, so false can grant both false and true)
                if grant_must_be_owner and not req_must_be_owner:
                    # Granter has must_be_owner=true, but requester wants must_be_owner=false
                    # Ownership-restricted capability can't grant unrestricted capability
                    continue

                # Both operation and ownership scope dominate!
                has_capability = True
                break

            if not has_capability:
                return False

        return True
    
    def _path_covers(self, grant_path: str, req_path: str) -> bool:
        """
        Check if grant_path pattern covers (is more general than) req_path pattern

        This is pattern-to-pattern comparison for capability subset validation,
        NOT runtime path matching. We're checking if the granter's capability
        pattern subsumes the requested capability pattern.

        Wildcard subsumption rules:
        - {...} subsumes everything (rest wildcard - matches any depth)
        - {any} subsumes {any}, {self}, {other}, and literals (one segment)
        - {self} only subsumes {self}
        - {other} only subsumes {other}
        - Literals only subsume identical literals

        Examples:
          grant="profiles/{any}" covers req="profiles/{self}/" → True
          grant="profiles/{self}" covers req="profiles/{any}/" → False
          grant="auth/users/{...}" covers req="auth/users/{any}/roles/admin" → True
          grant="auth/users/{any}" covers req="auth/users/{any}/roles/admin" → False
          grant="auth/users/{any}/{...}" covers req="auth/users/{any}/roles/{any}" → True
        """
        # Exact match
        if grant_path == req_path:
            return True

        # Normalize
        grant_norm = grant_path.strip('/')
        req_norm = req_path.strip('/')

        # Split into segments
        grant_parts = grant_norm.split('/')
        req_parts = req_norm.split('/')

        # Check if grant has {...} rest wildcard
        has_grant_rest = len(grant_parts) > 0 and grant_parts[-1] == '{...}'

        if has_grant_rest:
            # Grant has {...} - it covers anything with matching prefix
            grant_parts = grant_parts[:-1]  # Remove {...} for comparison
            # Grant prefix must not be longer than req
            if len(grant_parts) > len(req_parts):
                return False
            # Check prefix matches with wildcard subsumption
            for i, grant_seg in enumerate(grant_parts):
                req_seg = req_parts[i]
                if not self._wildcard_subsumes(grant_seg, req_seg):
                    return False
            # Prefix matched, {...} covers rest
            return True
        else:
            # Grant doesn't have {...} - must match exact depth (not prefix)
            # Both patterns must have same number of segments
            if len(grant_parts) != len(req_parts):
                return False

            # Check each segment with wildcard subsumption
            for i, grant_seg in enumerate(grant_parts):
                req_seg = req_parts[i]
                if not self._wildcard_subsumes(grant_seg, req_seg):
                    return False

            return True

    def _wildcard_subsumes(self, granter_seg: str, requested_seg: str) -> bool:
        """
        Check if granter's path segment subsumes requested segment.

        Subsumption rules:
        - {...} subsumes everything (rest wildcard)
        - {any} subsumes {any}, {self}, {other}, and literals
        - {self} only subsumes {self}
        - {other} only subsumes {other}
        - Literals only subsume identical literals
        """
        if granter_seg == '{...}':
            # Rest wildcard subsumes everything
            return True
        if granter_seg == '{any}':
            # {any} subsumes everything except {...}
            return requested_seg != '{...}'
        return granter_seg == requested_seg

    def verify_chain_of_trust(
        self,
        space_id: str,
        member_id: str,
        skip_cache: bool = False
    ) -> bool:
        """
        Verify that a member (user or tool) has a valid chain of trust back to the space admin.

        This prevents database tampering attacks where an adversary inserts a new public key
        directly into the database. Every member must have been added by someone who was
        themselves added by the admin (or by the admin directly).

        The chain of trust works as follows:
        1. Space admin's public key is the root of trust (same as space_id)
        2. Each user/tool entry at auth/users/{id} or auth/tools/{id} must be signed by
           someone who has a valid chain back to the space admin
        3. We recursively verify the chain by checking who signed each entry

        Args:
            space_id: Space identifier
            member_id: User or tool typed identifier to verify
            skip_cache: If True, bypass cache and re-validate (for testing)

        Returns:
            True if member has valid chain to space admin, False otherwise
        """
        # Check cache first (unless explicitly skipped)
        if not skip_cache:
            cache_key = (space_id, member_id)
            if cache_key in self._chain_validation_cache:
                return self._chain_validation_cache[cache_key]

        # Space admin is the root of trust
        try:
            space_pubkey = extract_public_key(space_id)
            member_pubkey = extract_public_key(member_id)
            if space_pubkey == member_pubkey:
                # Member IS the space admin - valid by definition
                result = True
                if not skip_cache:
                    self._chain_validation_cache[(space_id, member_id)] = result
                return result
        except Exception:
            # Invalid identifier format
            return False

        # Get the member's registration entry
        if self._is_tool(member_id):
            member_path = f"auth/tools/{member_id}"
        else:
            member_path = f"auth/users/{member_id}"

        member_entry = self.state_store.get_state(space_id, member_path)
        if not member_entry:
            # Member not registered in space
            return False

        # Verify the member entry's signature
        if not self._verify_state_entry_signature(space_id, member_entry):
            print(f"Chain validation failed: Invalid signature on {member_path}")
            return False

        # Get who signed this member's entry
        signed_by = member_entry.get("signed_by")
        if not signed_by:
            print(f"Chain validation failed: No signed_by field in {member_path}")
            return False

        # Recursively verify the signer's chain
        # This prevents infinite loops because:
        # 1. Space admin case returns immediately (base case)
        # 2. Each member can only be signed once (no cycles in state)
        # 3. Maximum depth is bounded by the number of members in the space
        signer_valid = self.verify_chain_of_trust(space_id, signed_by, skip_cache)

        if not signer_valid:
            print(f"Chain validation failed: Signer {signed_by} is not valid for {member_id}")

        # Cache the result
        if not skip_cache:
            self._chain_validation_cache[(space_id, member_id)] = signer_valid

        return signer_valid

    def invalidate_chain_cache(self, space_id: str, member_id: Optional[str] = None) -> None:
        """
        Invalidate chain validation cache.

        Call this when a member is added, removed, or their entry is modified.

        Args:
            space_id: Space identifier
            member_id: If provided, only invalidate this member. Otherwise invalidate entire space.
        """
        if member_id:
            # Invalidate specific member
            cache_key = (space_id, member_id)
            self._chain_validation_cache.pop(cache_key, None)
        else:
            # Invalidate entire space
            keys_to_remove = [k for k in self._chain_validation_cache.keys() if k[0] == space_id]
            for key in keys_to_remove:
                del self._chain_validation_cache[key]

    def verify_tool_creation(
        self,
        space_id: str,
        path: str,
        tool_data: dict,
        creator_public_key: str,
        signature_b64: str
    ) -> bool:
        """
        Verify that a tool creation is valid.

        According to AUTHORIZATION.md, a tool can only be created if:
        1. Creator has 'create' or 'write' permission on auth/tools/{tool_id}
        2. Creator has superset permission for each capability being granted to the tool
        3. Tool definition is properly signed by creator
        4. Path-content consistency: tool_id in data matches path

        Args:
            space_id: Typed space identifier
            path: State path where tool is being defined (auth/tools/{tool_id})
            tool_data: The tool metadata being created
            creator_public_key: Typed user identifier of creator
            signature_b64: Base64-encoded signature

        Returns:
            True if tool creation is valid
        """
        # Verify path-content consistency
        # Path format: auth/tools/{tool_id}
        parts = path.strip('/').split('/')
        if len(parts) != 3 or parts[0] != 'auth' or parts[1] != 'tools':
            return False

        tool_id_from_path = parts[2]
        tool_id_from_data = tool_data.get('tool_id')

        if tool_id_from_path != tool_id_from_data:
            print(f"Tool creation rejected: tool_id mismatch (path='{tool_id_from_path}', data='{tool_id_from_data}')")
            return False

        # Verify signature
        # TODO: Implement proper signature verification for tool creation
        # For now, trust state write validation

        # Space creator can create any tool
        try:
            creator_bytes = extract_public_key(creator_public_key)
            space_bytes = extract_public_key(space_id)
            if creator_bytes == space_bytes:
                return True
        except Exception:
            pass

        # Load creator's capabilities
        creator_direct_caps = self._load_user_capabilities(space_id, creator_public_key)
        creator_role_caps = self._load_role_capabilities(space_id, creator_public_key)
        creator_all_caps = creator_direct_caps + creator_role_caps

        # Check if creator has permission to create this specific tool
        can_create_tools = False
        for cap in creator_all_caps:
            if self._capability_grants_permission(
                cap,
                "create",
                path,  # Check permission for the actual path being created
                creator_public_key
            ):
                can_create_tools = True
                break

        if not can_create_tools:
            return False

        # Load tool's capabilities to verify creator has superset
        tool_cap_prefix = f"auth/tools/{tool_id_from_path}/rights/"
        tool_cap_states = self.state_store.list_state(space_id, tool_cap_prefix)

        tool_capabilities = []
        for cap_state in tool_cap_states:
            # Verify state entry signature first
            if not self._verify_state_entry_signature(space_id, cap_state):
                print(f"Invalid state entry signature for tool capability {cap_state.get('path', 'unknown')}")
                continue

            try:
                cap_decoded = base64.b64decode(cap_state["data"])
                cap = json.loads(cap_decoded)
                tool_capabilities.append(cap)
            except Exception as e:
                print(f"Failed to decode tool capability: {e}")
                continue

        # If tool has no capabilities, creation is allowed (already checked can_create_tools)
        if not tool_capabilities:
            return True

        # Check if creator has superset of all tool capabilities
        # This prevents privilege escalation through tool creation
        return self._has_capability_superset(
            creator_all_caps,
            tool_capabilities
        )
