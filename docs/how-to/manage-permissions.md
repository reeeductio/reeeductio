# Manage Permissions

This guide covers creating roles, defining capabilities, assigning roles to users, and revoking access.

For a conceptual overview, see [Access Control](../concepts/access-control.md).

## Overview

Permissions flow like this:

1. **Create a role** (e.g. `"member"`, `"moderator"`)
2. **Grant capabilities** to the role (what operations it can perform on which paths)
3. **Assign the role** to users

You can also grant capabilities directly to a user without going through a role.

## Creating a role

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

    space.create_role('member')
    space.create_role('moderator', description='Can delete messages and manage topics')
    ```

=== "CLI"

    ```bash
    reeeductio-admin role create member
    reeeductio-admin role create moderator --description "Can delete messages and manage topics"
    ```

## Granting capabilities to a role

A capability specifies an `op` (operation) and a `path` (resource). The path supports wildcards.

### Available operations

| Op | Meaning |
|----|---------|
| `read` | Read-only |
| `create` | Write, only if the resource does not already exist |
| `modify` | Write, only if the resource already exists |
| `delete` | Delete an existing resource |
| `write` | Full write (create + modify + delete) |

### Path wildcards

| Wildcard | Matches |
|----------|---------|
| `{any}` | Exactly one path segment |
| `{...}` | Any number of segments |
| `{self}` | The authenticated user's own ID |

### Examples

=== "Python"

    ```python
    # Read all topics
    space.grant_capability_to_role(
        role_name='member',
        cap_id='read-all-topics',
        capability={'op': 'read', 'path': 'topics/{any}'},
    )

    # Post to all topics
    space.grant_capability_to_role(
        role_name='member',
        cap_id='post-all-topics',
        capability={'op': 'create', 'path': 'topics/{any}/messages/{any}'},
    )

    # Read and write own profile only
    space.grant_capability_to_role(
        role_name='member',
        cap_id='own-profile',
        capability={'op': 'write', 'path': 'state/profiles/{self}'},
    )

    # Moderator can delete any message
    space.grant_capability_to_role(
        role_name='moderator',
        cap_id='delete-messages',
        capability={'op': 'delete', 'path': 'topics/{any}/messages/{any}'},
    )
    ```

=== "CLI"

    ```bash
    reeeductio-admin role grant member \
        --cap-id read-all-topics \
        --op read \
        --path "topics/{any}"

    reeeductio-admin role grant member \
        --cap-id post-all-topics \
        --op create \
        --path "topics/{any}/messages/{any}"

    reeeductio-admin role grant member \
        --cap-id own-profile \
        --op write \
        --path "state/profiles/{self}"

    reeeductio-admin role grant moderator \
        --cap-id delete-messages \
        --op delete \
        --path "topics/{any}/messages/{any}"
    ```

## Assigning a role to a user

=== "Python"

    ```python
    space.assign_role_to_user('U...', 'member')
    space.assign_role_to_user('U...', 'moderator')  # can have multiple roles
    ```

=== "CLI"

    ```bash
    reeeductio-admin user assign-role U... --role member
    reeeductio-admin user assign-role U... --role moderator
    ```

## Granting a capability directly to a user

For one-off permissions that don't fit a role:

=== "Python"

    ```python
    space.grant_capability_to_user(
        user_id='U...',
        cap_id='read-audit',
        capability={'op': 'read', 'path': 'topics/audit-log'},
    )
    ```

=== "CLI"

    ```bash
    reeeductio-admin user grant U... \
        --cap-id read-audit \
        --op read \
        --path "topics/audit-log"
    ```

## Revoking a role or capability

Roles and capabilities are stored as state entries. To revoke, set the entry to empty:

=== "Python"

    ```python
    # Revoke a role assignment
    space.set_plaintext_state(f'auth/users/{user_id}/roles/member', '')

    # Revoke a direct capability
    space.set_plaintext_state(f'auth/users/{user_id}/rights/read-audit', '')
    ```

## Common permission patterns

### Read-only guest

```python
space.create_role('guest')
space.grant_capability_to_role('guest', 'read-topics', {'op': 'read', 'path': 'topics/{any}'})
```

### Full member (read + post, not delete)

```python
space.create_role('member')
space.grant_capability_to_role('member', 'read-topics', {'op': 'read', 'path': 'topics/{any}'})
space.grant_capability_to_role('member', 'post-topics', {'op': 'create', 'path': 'topics/{any}/messages/{any}'})
space.grant_capability_to_role('member', 'own-profile', {'op': 'write', 'path': 'state/profiles/{self}'})
```

### Moderator (read + post + delete messages)

```python
space.create_role('moderator')
space.grant_capability_to_role('moderator', 'all-topics', {'op': 'write', 'path': 'topics/{any}'})
```

### Service account (write-only to one topic)

```python
space.create_tool('T...')
space.grant_capability_to_tool('T...', 'post-alerts', {'op': 'create', 'path': 'topics/alerts/messages/{any}'})
```

See [Tool Accounts](tool-accounts.md) for the full guide on service accounts.

## Related

- [Access Control](../concepts/access-control.md) — concept overview
- [Add Users](add-users.md) — adding users before assigning roles
- [Tool Accounts](tool-accounts.md) — permissions for bots and services
