# Security Considerations

## Key Derivation (HKDF)

### Domain Separation with space_id and topic_id

The SDK includes the `space_id` in the HKDF `info` parameter for all derived keys:

```python
message_key = HKDF(symmetric_root, info="message key | {space_id}")
blob_key = HKDF(symmetric_root, info="blob key | {space_id}")
data_key = HKDF(symmetric_root, info="data key | {space_id}")
```

Keys for topics within the space are generated from the `message_key` and the `topic_id`.

```python
topic_key = HKDF(message_key, info=f"topic key | {topic_id}")
```

The space's `state_key` is just the topic key for the "state" topic.

```python
state_key = HKDF(message_key, info="topic key | state")
```

## Threat Model

### In Scope
- Accidental key reuse across spaces ✓ Mitigated
- Malicious server attempting to decrypt data ✓ Zero-knowledge design
- Network eavesdropping ✓ End-to-end encryption

### Out of Scope
- Compromised client device (attacker has access to symmetric_root)
- Side-channel attacks on cryptographic operations
- Social engineering attacks

## Security Audit

This SDK has not been formally audited. Use at your own risk.

For production deployments:
- Conduct professional security audit
- Use hardware security modules (HSMs) for key storage
- Implement key rotation policies
- Monitor for unusual access patterns
