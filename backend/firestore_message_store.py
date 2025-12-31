"""
Firestore implementation of MessageStore for E2EE messaging system

Uses Google Cloud Firestore for message persistence with blockchain-style
message chains per topic. Supports multi-instance deployments with automatic
consistency and efficient time-range queries.
"""

from typing import Optional, List, Dict, Any
from google.cloud import firestore
from message_store import MessageStore


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
        channel_id: str,
        topic_id: str,
        message_hash: str,
        prev_hash: Optional[str],
        encrypted_payload: str,
        sender: str,
        signature: str,
        server_timestamp: int
    ) -> None:
        """
        Add a new message to a topic using a batched write for atomicity

        The batch ensures that both the message document and the chain head
        update succeed or fail together.
        """
        batch = self.db.batch()

        # Add message document
        msg_ref = self.db.collection('channels').document(channel_id) \
                        .collection('topics').document(topic_id) \
                        .collection('messages').document(message_hash)

        batch.set(msg_ref, {
            'message_hash': message_hash,
            'prev_hash': prev_hash,
            'encrypted_payload': encrypted_payload,
            'sender': sender,
            'signature': signature,
            'server_timestamp': server_timestamp
        })

        # Update chain head in topic document
        topic_ref = self.db.collection('channels').document(channel_id) \
                          .collection('topics').document(topic_id)

        batch.set(topic_ref, {
            'chain_head': message_hash,
            'last_updated': server_timestamp
        }, merge=True)

        # Commit both operations atomically
        batch.commit()

    def get_messages(
        self,
        channel_id: str,
        topic_id: str,
        from_ts: Optional[int] = None,
        to_ts: Optional[int] = None,
        limit: int = 100
    ) -> List[Dict[str, Any]]:
        """
        Query messages with time-based filtering

        Uses indexed queries on server_timestamp for efficient retrieval.
        Results are returned in chronological order.
        """
        query = self.db.collection('channels').document(channel_id) \
                      .collection('topics').document(topic_id) \
                      .collection('messages') \
                      .order_by('server_timestamp')

        # Apply time range filters
        if from_ts is not None:
            query = query.where('server_timestamp', '>=', from_ts)
        if to_ts is not None:
            query = query.where('server_timestamp', '<=', to_ts)

        # Apply limit
        query = query.limit(limit)

        # Execute query and convert to list
        results = []
        for doc in query.stream():
            data = doc.to_dict()
            results.append({
                'message_hash': data['message_hash'],
                'topic_id': topic_id,  # Add topic_id for consistency
                'prev_hash': data['prev_hash'],
                'encrypted_payload': data['encrypted_payload'],
                'sender': data['sender'],
                'signature': data['signature'],
                'server_timestamp': data['server_timestamp']
            })

        return results

    def get_message_by_hash(
        self,
        channel_id: str,
        topic_id: str,
        message_hash: str
    ) -> Optional[Dict[str, Any]]:
        """
        Get a specific message by its hash

        With topic_id provided, this is a direct document lookup - very fast!
        No index needed, no collection group query required.
        """
        doc_ref = self.db.collection('channels').document(channel_id) \
                        .collection('topics').document(topic_id) \
                        .collection('messages').document(message_hash)

        doc = doc_ref.get()
        if not doc.exists:
            return None

        data = doc.to_dict()
        return {
            'message_hash': data['message_hash'],
            'topic_id': topic_id,  # Add topic_id for consistency
            'prev_hash': data['prev_hash'],
            'encrypted_payload': data['encrypted_payload'],
            'sender': data['sender'],
            'signature': data['signature'],
            'server_timestamp': data['server_timestamp']
        }

    def get_chain_head(
        self,
        channel_id: str,
        topic_id: str
    ) -> Optional[Dict[str, Any]]:
        """
        Get the most recent message in a topic (chain head)

        Reads from the topic document which is updated atomically
        with each message addition.
        """
        topic_ref = self.db.collection('channels').document(channel_id) \
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
