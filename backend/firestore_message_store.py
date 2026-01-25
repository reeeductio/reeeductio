"""
Firestore implementation of MessageStore for E2EE messaging system

Uses Google Cloud Firestore for message persistence with blockchain-style
message chains per topic. Supports multi-instance deployments with automatic
consistency and efficient time-range queries.
"""

from typing import Optional, List, Dict, Any
from google.cloud import firestore
from google.cloud.firestore_v1.base_query import FieldFilter
from message_store import MessageStore
from exceptions import ChainConflictError


class FirestoreMessageStore(MessageStore):
    """Firestore-based message storage implementation"""

    def __init__(self, project_id: Optional[str] = None, database_id: str = "(default)"):
        """
        Initialize Firestore message store

        Args:
            project_id: GCP project ID (uses default credentials if None)
            database_id: Firestore database ID (default: "(default)")
        """
        super().__init__()
        # No cache for remote storage (multi-instance safety)
        self._cache = None

        if project_id:
            self.db = firestore.Client(project=project_id, database=database_id)
        else:
            self.db = firestore.Client(database=database_id)

    def add_message(
        self,
        space_id: str,
        topic_id: str,
        message_hash: str,
        msg_type: str,
        prev_hash: Optional[str],
        data: str,
        sender: str,
        signature: str,
        server_timestamp: int
    ) -> None:
        """
        Add a new message to a topic with atomic chain validation.

        This implements compare-and-swap (CAS) on the chain head to prevent
        race conditions. The transaction ensures atomicity between checking
        the current head and inserting the new message.

        Raises:
            ChainConflictError: If prev_hash doesn't match current chain head
        """
        @firestore.transactional
        def add_message_transaction(transaction):
            # Get references
            topic_ref = self.db.collection('spaces').document(space_id) \
                              .collection('topics').document(topic_id)

            msg_ref = self.db.collection('spaces').document(space_id) \
                            .collection('topics').document(topic_id) \
                            .collection('messages').document(message_hash)

            # Get current chain head (within transaction for atomicity)
            topic_doc = topic_ref.get(transaction=transaction)

            if topic_doc.exists:
                topic_data = topic_doc.to_dict()
                current_head = topic_data.get('chain_head')
            else:
                current_head = None

            # Validate chain continuity (CAS condition)
            if current_head != prev_hash:
                # Format error message with truncated hashes
                if current_head is None:
                    expected = "None (first message)"
                else:
                    expected = current_head[:16] + "..."
                if prev_hash is None:
                    got = "None"
                else:
                    got = prev_hash[:16] + "..."

                raise ChainConflictError(
                    f"Chain conflict in topic '{topic_id}': "
                    f"expected prev_hash={expected}, got {got}. "
                    f"Another message was added concurrently."
                )

            # Insert message (chain validated - we own the new head)
            transaction.set(msg_ref, {
                'message_hash': message_hash,
                'type': msg_type,
                'prev_hash': prev_hash,
                'data': data,
                'sender': sender,
                'signature': signature,
                'server_timestamp': server_timestamp
            })

            # Update chain head
            transaction.set(topic_ref, {
                'chain_head': message_hash,
                'last_updated': server_timestamp
            }, merge=True)

        # Execute transaction
        transaction = self.db.transaction()
        add_message_transaction(transaction)

    def get_messages(
        self,
        space_id: str,
        topic_id: str,
        from_ts: Optional[int] = None,
        to_ts: Optional[int] = None,
        limit: int = 100
    ) -> List[Dict[str, Any]]:
        """
        Query messages with time-based filtering

        Uses indexed queries on server_timestamp for efficient retrieval.
        Results are returned in chronological order unless from_ts > to_ts,
        in which case they are returned in reverse-chronological order.
        """
        reverse_order = (
            from_ts is not None and
            to_ts is not None and
            from_ts > to_ts
        )
        range_start = to_ts if reverse_order else from_ts
        range_end = from_ts if reverse_order else to_ts

        query = self.db.collection('spaces').document(space_id) \
                      .collection('topics').document(topic_id) \
                      .collection('messages') \
                      .order_by('server_timestamp')

        # Apply time range filters
        if range_start is not None:
            query = query.where(filter=FieldFilter('server_timestamp', '>=', range_start))
        if range_end is not None:
            query = query.where(filter=FieldFilter('server_timestamp', '<=', range_end))

        # Apply limit
        if reverse_order:
            query = query.limit_to_last(limit)
        else:
            query = query.limit(limit)

        # Execute query and convert to list
        results = []
        docs = query.get() if reverse_order else query.stream()
        for doc in docs:
            doc_data = doc.to_dict()
            results.append({
                'message_hash': doc_data['message_hash'],
                'topic_id': topic_id,  # Add topic_id for consistency
                'type': doc_data['type'],
                'prev_hash': doc_data['prev_hash'],
                'data': doc_data['data'],
                'sender': doc_data['sender'],
                'signature': doc_data['signature'],
                'server_timestamp': doc_data['server_timestamp']
            })

        if reverse_order:
            results.reverse()
        if results or not reverse_order:
            return results

        # Fallback for reverse-order queries that unexpectedly return empty.
        # Use the chain head and direct lookup to avoid missing the latest message.
        head = self.get_chain_head(space_id, topic_id)
        if not head:
            return results
        head_hash = head.get('message_hash')
        if not head_hash:
            return results

        message = self.get_message_by_hash(space_id, topic_id, head_hash)
        if not message:
            return results

        ts = message.get('server_timestamp')
        if ts is None:
            return results
        if range_start is not None and ts < range_start:
            return results
        if range_end is not None and ts > range_end:
            return results

        return [message]

    def get_message_by_hash(
        self,
        space_id: str,
        topic_id: str,
        message_hash: str
    ) -> Optional[Dict[str, Any]]:
        """
        Get a specific message by its hash

        With topic_id provided, this is a direct document lookup - very fast!
        No index needed, no collection group query required.
        """
        doc_ref = self.db.collection('spaces').document(space_id) \
                        .collection('topics').document(topic_id) \
                        .collection('messages').document(message_hash)

        doc = doc_ref.get()
        if not doc.exists:
            return None

        doc_data = doc.to_dict()
        return {
            'message_hash': doc_data['message_hash'],
            'topic_id': topic_id,  # Add topic_id for consistency
            'type': doc_data['type'],
            'prev_hash': doc_data['prev_hash'],
            'data': doc_data['data'],
            'sender': doc_data['sender'],
            'signature': doc_data['signature'],
            'server_timestamp': doc_data['server_timestamp']
        }

    def get_chain_head(
        self,
        space_id: str,
        topic_id: str
    ) -> Optional[Dict[str, Any]]:
        """
        Get the most recent message in a topic (chain head)

        Reads from the topic document which is updated atomically
        with each message addition.
        """
        topic_ref = self.db.collection('spaces').document(space_id) \
                          .collection('topics').document(topic_id)

        doc = topic_ref.get()
        if not doc.exists:
            return None

        data = doc.to_dict()
        if 'chain_head' not in data:
            return None

        return {
            'message_hash': data['chain_head']
        }

    def get_most_recent_message(
        self,
        space_id: str,
        topic_id: str,
        type: str
    ) -> Optional[Dict[str, Any]]:
        """
        Get the most recent message of a given type

        Uses indexed query on server_timestamp filtered by type for efficient retrieval.
        """
        query = self.db.collection('spaces').document(space_id) \
                      .collection('topics').document(topic_id) \
                      .collection('messages') \
                      .where(filter=FieldFilter('type', '==', type)) \
                      .order_by('server_timestamp', direction=firestore.Query.DESCENDING) \
                      .limit(1)

        # Execute query
        docs = list(query.stream())
        if not docs:
            return None

        doc_data = docs[0].to_dict()
        return {
            'message_hash': doc_data['message_hash'],
            'topic_id': topic_id,
            'type': doc_data['type'],
            'prev_hash': doc_data['prev_hash'],
            'data': doc_data['data'],
            'sender': doc_data['sender'],
            'signature': doc_data['signature'],
            'server_timestamp': doc_data['server_timestamp']
        }

    def initialize_tool_usage(self, space_id: str, tool_id: str) -> None:
        """Initialize tool usage tracking for a use-limited tool."""
        doc_ref = self.db.collection('spaces').document(space_id) \
                        .collection('tool_usage').document(tool_id)

        doc_ref.set({
            'use_count': 0,
            'last_used_at': None
        })

    def increment_tool_usage(self, space_id: str, tool_id: str, timestamp: int) -> int:
        """
        Increment tool use count and return new count using Firestore transaction.

        This is operational metadata (NOT part of space state).

        Args:
            space_id: Space identifier
            tool_id: Tool identifier (T_*)
            timestamp: Current timestamp in milliseconds

        Returns:
            New use count after increment
        """
        doc_ref = self.db.collection('spaces').document(space_id) \
                        .collection('tool_usage').document(tool_id)

        @firestore.transactional
        def update_in_transaction(transaction, doc_ref):
            snapshot = doc_ref.get(transaction=transaction)

            if snapshot.exists:
                # Increment existing count
                current_count = snapshot.get('use_count')
                new_count = current_count + 1
                transaction.update(doc_ref, {
                    'use_count': new_count,
                    'last_used_at': timestamp
                })
                return new_count
            else:
                # Tool not initialized
                raise ValueError(f"Tool {tool_id} not initialized for space {space_id}")

        transaction = self.db.transaction()
        return update_in_transaction(transaction, doc_ref)

    def get_tool_usage(self, space_id: str, tool_id: str) -> Optional[Dict[str, Any]]:
        """
        Get tool usage statistics from Firestore.

        This is operational metadata (NOT part of space state).

        Args:
            space_id: Space identifier
            tool_id: Tool identifier (T_*)

        Returns:
            Dictionary with use_count and last_used_at, or None if not found
        """
        doc_ref = self.db.collection('spaces').document(space_id) \
                        .collection('tool_usage').document(tool_id)

        doc = doc_ref.get()
        if not doc.exists:
            return None

        data = doc.to_dict()
        return {
            'use_count': data['use_count'],
            'last_used_at': data.get('last_used_at')
        }
