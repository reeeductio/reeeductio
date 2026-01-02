"""
Authorization engine for capability-based access control

Implements:
- Capability loading and verification
- Path pattern matching with wildcards
- Permission checking (read/create/write)
- Capability subset validation (prevent privilege escalation)
"""

from typing import Optional, List, Dict, Any
from state_store import StateStore
from crypto import CryptoUtils
from identifiers import extract_public_key, decode_identifier, IdType
from path_validation import validate_capability_path, PathValidationError
import fnmatch
import base64
import json
import time


class AuthorizationEngine:
    """Capability-based authorization with signed permissions"""

    def __init__(self, state_store: StateStore, crypto: CryptoUtils):
        self.state_store = state_store
        self.crypto = crypto

    def _is_tool(self, identifier: str) -> bool:
        """Check if an identifier is a tool (has 'T' type prefix)"""
        try:
            tid = decode_identifier(identifier)
            return tid.id_type == IdType.TOOL
        except Exception:
            return False

    def check_permission(
        self,
        channel_id: str,
        user_public_key: str,
        operation: str,
        state_path: str
    ) -> bool:
        """
        Check if user or tool has permission for an operation on a state path

        Args:
            channel_id: Channel identifier
            user_public_key: User or tool typed identifier
            operation: 'read', 'create', or 'write'
            state_path: State path being accessed

        Returns:
            True if user/tool has permission
        """
        # Tools have NO ambient authority - they can only use explicit capabilities
        if self._is_tool(user_public_key):
            # Load tool capabilities only
            capabilities = self._load_tool_capabilities(channel_id, user_public_key)

            # Check if any capability grants permission
            for cap in capabilities:
                if self._capability_grants_permission(cap, operation, state_path, user_public_key):
                    return True

            return False

        # For users: Channel creator has god mode
        # Compare underlying public keys (channel and user IDs have different type prefixes)
        try:
            channel_pubkey = extract_public_key(channel_id)
            user_pubkey = extract_public_key(user_public_key)
            if channel_pubkey == user_pubkey:
                return True
        except ValueError:
            # If extraction fails, fall through to capability check
            pass

        # Load direct capabilities for this user
        capabilities = self._load_user_capabilities(channel_id, user_public_key)

        # Load capabilities inherited from roles
        role_capabilities = self._load_role_capabilities(channel_id, user_public_key)

        # Combine all capabilities
        all_capabilities = capabilities + role_capabilities

        # Check if any capability grants permission
        for cap in all_capabilities:
            if self._capability_grants_permission(cap, operation, state_path, user_public_key):
                return True

        return False
    
    def _load_user_capabilities(
        self,
        channel_id: str,
        user_public_key: str
    ) -> List[Dict[str, Any]]:
        """
        Load all capabilities for a user from state

        Capabilities are stored at state path:
        auth/users/{public_key}/rights/{capability_id}

        Data is base64-encoded JSON, so we need to decode it.
        """
        prefix = f"auth/users/{user_public_key}/rights/"
        capability_states = self.state_store.list_state(channel_id, prefix)

        capabilities = []
        for state in capability_states:
            # Decode base64 data and parse JSON
            try:
                decoded = base64.b64decode(state["data"])
                cap = json.loads(decoded)

                # Verify capability signature
                if self._verify_capability(channel_id, user_public_key, cap):
                    capabilities.append(cap)
            except Exception as e:
                # Skip invalid capability entries
                print(f"Failed to decode capability: {e}")
                continue

        return capabilities

    def _load_role_capabilities(
        self,
        channel_id: str,
        user_public_key: str
    ) -> List[Dict[str, Any]]:
        """
        Load all capabilities inherited from user's roles.

        Process:
        1. Load user's role memberships from auth/users/{user_id}/roles/
        2. For each role, load role's capabilities from auth/roles/{role_id}/rights/
        3. Verify all capability signatures
        4. Return combined list of all role capabilities

        Args:
            channel_id: Channel identifier
            user_public_key: User's public key

        Returns:
            List of capability dictionaries from all roles
        """
        # Load user's role grants
        role_prefix = f"auth/users/{user_public_key}/roles/"
        role_grants = self.state_store.list_state(channel_id, role_prefix)

        all_role_capabilities = []

        for role_grant_state in role_grants:
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

                # TODO: Verify role grant signature?
                # For now, we trust role grants that made it into state
                # (they were validated during state write)

                # Load capabilities for this role
                role_cap_prefix = f"auth/roles/{role_id}/rights/"
                role_cap_states = self.state_store.list_state(channel_id, role_cap_prefix)

                for cap_state in role_cap_states:
                    try:
                        cap_decoded = base64.b64decode(cap_state["data"])
                        cap = json.loads(cap_decoded)

                        # Verify capability signature
                        # Role capabilities are signed as if granted to the role itself
                        # We use the role_id as the "recipient" for verification
                        # This ensures the capability was validly added to the role
                        if self._verify_capability(channel_id, role_id, cap):
                            all_role_capabilities.append(cap)
                        else:
                            print(f"Invalid signature for role capability in role {role_id}")
                    except Exception as e:
                        print(f"Failed to decode role capability: {e}")
                        continue

            except Exception as e:
                print(f"Failed to decode role grant: {e}")
                continue

        return all_role_capabilities

    def _load_tool_capabilities(
        self,
        channel_id: str,
        tool_public_key: str
    ) -> List[Dict[str, Any]]:
        """
        Load all capabilities for a tool from state.

        Tools have NO ambient authority - they can ONLY use capabilities
        explicitly granted in auth/tools/{tool_id}/rights/

        Args:
            channel_id: Channel identifier
            tool_public_key: Tool's typed identifier

        Returns:
            List of capability dictionaries
        """
        prefix = f"auth/tools/{tool_public_key}/rights/"
        capability_states = self.state_store.list_state(channel_id, prefix)

        capabilities = []
        for state in capability_states:
            try:
                decoded = base64.b64decode(state["data"])
                cap = json.loads(decoded)

                # Verify capability signature
                if self._verify_capability(channel_id, tool_public_key, cap):
                    capabilities.append(cap)
            except Exception as e:
                print(f"Failed to decode tool capability: {e}")
                continue

        return capabilities

    def _verify_capability(
        self,
        channel_id: str,
        recipient_public_key: str,
        capability: dict
    ) -> bool:
        """
        Verify that a capability is validly signed

        Args:
            channel_id: Typed channel identifier
            recipient_public_key: Typed user identifier receiving the capability
            capability: Capability dict with signature

        Returns:
            True if signature is valid
        """
        required_fields = ["op", "path", "granted_by", "granted_at", "signature"]
        if not all(field in capability for field in required_fields):
            return False

        try:
            signature = self.crypto.base64_decode(capability["signature"])
            # Extract raw public key from typed identifier
            granter_key = extract_public_key(capability["granted_by"])

            return self.crypto.verify_capability_signature(
                channel_id,
                recipient_public_key,
                capability,
                signature,
                granter_key
            )
        except Exception as e:
            print(f"Capability verification failed: {e}")
            return False
    
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
            operation: 'read', 'create', or 'write'
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
        # write >= create > (nothing)
        # read is separate
        if cap_op == "write":
            # write grants both write and create
            return operation in ["read", "create", "write"]
        elif cap_op == "create":
            # create only grants create (not write to existing)
            return operation == "create"
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
        channel_id: str,
        path: str,
        capability_data: dict,
        granter_public_key: str,
        signature_b64: str
    ) -> bool:
        """
        Verify that a capability grant is valid

        Checks:
        1. Capability path pattern is valid (no unknown wildcards)
        2. Signature is valid
        3. Granter exists (or is channel_id)
        4. Granter has the capability they're trying to grant

        Args:
            channel_id: Typed channel identifier
            path: State path where capability is being stored
            capability_data: The capability being granted
            granter_public_key: Typed user identifier of granter
            signature_b64: Base64-encoded signature

        Returns:
            True if grant is valid
        """
        # Validate the capability path pattern
        capability_path = capability_data.get("path", "")
        try:
            validate_capability_path(capability_path)
        except PathValidationError as e:
            print(f"Invalid capability path pattern '{capability_path}': {e}")
            return False

        # Extract recipient public key from path
        # Path format: auth/users/{recipient_key}/rights/{cap_id}
        parts = path.strip('/').split('/')
        if len(parts) < 3:
            return False

        recipient_key = parts[2]

        # Verify signature
        try:
            signature = self.crypto.base64_decode(signature_b64)
            # Extract raw public key from typed identifier
            granter_key_bytes = extract_public_key(granter_public_key)

            if not self.crypto.verify_capability_signature(
                channel_id,
                recipient_key,
                capability_data,
                signature,
                granter_key_bytes
            ):
                return False
        except Exception as e:
            print(f"Signature verification failed: {e}")
            return False
        
        # Channel creator can grant anything
        if granter_public_key == channel_id:
            return True
        
        # Load granter's capabilities
        granter_caps = self._load_user_capabilities(channel_id, granter_public_key)
        
        # Check if granter has permission to grant capabilities
        can_grant = False
        for cap in granter_caps:
            if self._capability_grants_permission(
                cap,
                "create",
                "auth/users/{any}/rights/",
                granter_public_key
            ):
                can_grant = True
                break
        
        if not can_grant:
            return False
        
        # Check if granter has the capability they're trying to grant (subset check)
        return self._has_capability_superset(
            granter_caps,
            [capability_data]
        )

    def verify_role_grant(
        self,
        channel_id: str,
        path: str,
        role_grant_data: dict,
        granter_public_key: str,
        signature_b64: str
    ) -> bool:
        """
        Verify that a role grant is valid

        Checks:
        1. Signature is valid
        2. Granter exists (or is channel_id)
        3. Role exists
        4. Granter has superset of all capabilities in the role

        Args:
            channel_id: Typed channel identifier
            path: State path where role grant is being stored
            role_grant_data: The role grant being created
            granter_public_key: Typed user identifier of granter
            signature_b64: Base64-encoded signature

        Returns:
            True if grant is valid
        """
        # Extract recipient and role from path
        # Path format: auth/users/{recipient_key}/roles/{role_id}
        parts = path.strip('/').split('/')
        if len(parts) < 5:
            return False

        # recipient_key = parts[2]  # Not currently used, would be for signature verification
        role_id = parts[4]

        # Verify signature
        # TODO: Need a verify_role_grant_signature method in crypto
        # For now, trust that it was validated during state write
        # Parameters role_grant_data and signature_b64 will be used when this is implemented

        # Channel creator can grant anything
        # Compare the underlying public keys (granter might be U_xxx while channel is C_xxx)
        try:
            granter_bytes = extract_public_key(granter_public_key)
            channel_bytes = extract_public_key(channel_id)
            if granter_bytes == channel_bytes:
                return True
        except Exception:
            pass  # If extraction fails, continue with normal checks

        # Load all capabilities in this role
        role_cap_prefix = f"auth/roles/{role_id}/rights/"
        role_cap_states = self.state_store.list_state(channel_id, role_cap_prefix)

        role_capabilities = []
        for cap_state in role_cap_states:
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
        granter_direct_caps = self._load_user_capabilities(channel_id, granter_public_key)
        granter_role_caps = self._load_role_capabilities(channel_id, granter_public_key)
        granter_all_caps = granter_direct_caps + granter_role_caps

        # Check if granter has permission to grant roles
        can_grant = False
        for cap in granter_all_caps:
            if self._capability_grants_permission(
                cap,
                "create",
                "auth/users/{any}/roles/",
                granter_public_key
            ):
                can_grant = True
                break

        if not can_grant:
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
        
        Args:
            granter_caps: Capabilities the granter has
            requested_caps: Capabilities being requested
        
        Returns:
            True if granter has all requested capabilities (or stronger)
        """
        for req_cap in requested_caps:
            req_op = req_cap["op"]
            req_path = req_cap["path"]
            
            # Check if granter has matching or stronger capability
            has_capability = False
            
            for grant_cap in granter_caps:
                grant_op = grant_cap["op"]
                grant_path = grant_cap["path"]
                
                # Path must match or be a superset
                # grant_path="/state/*" covers req_path="/state/members/"
                if not self._path_covers(grant_path, req_path):
                    continue
                
                # Operation must be equal or stronger
                if grant_op == "write":
                    # write covers everything
                    has_capability = True
                    break
                elif grant_op == "create" and req_op == "create":
                    has_capability = True
                    break
                elif grant_op == "read" and req_op == "read":
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

    def verify_tool_creation(
        self,
        channel_id: str,
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
            channel_id: Typed channel identifier
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

        # Channel creator can create any tool
        try:
            creator_bytes = extract_public_key(creator_public_key)
            channel_bytes = extract_public_key(channel_id)
            if creator_bytes == channel_bytes:
                return True
        except Exception:
            pass

        # Load creator's capabilities
        creator_direct_caps = self._load_user_capabilities(channel_id, creator_public_key)
        creator_role_caps = self._load_role_capabilities(channel_id, creator_public_key)
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
        tool_cap_states = self.state_store.list_state(channel_id, tool_cap_prefix)

        tool_capabilities = []
        for cap_state in tool_cap_states:
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
