"""
Firestore implementation of DataStore for E2EE messaging system

Uses Google Cloud Firestore (in Datastore mode) for state persistence.
Supports multi-instance deployments with automatic consistency.
"""

from typing import Optional, List, Dict, Any
from google.cloud import firestore
from google.cloud.firestore_v1.base_query import FieldFilter
from data_store import DataStore


class FirestoreDataStore(DataStore):
    """Firestore-based state storage implementation"""

    def __init__(self, project_id: Optional[str] = None, database_id: str = "(default)"):
        """
        Initialize Firestore state store

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

    @staticmethod
    def _encode_path(path: str) -> str:
        """
        Encode path for use as Firestore document ID

        Firestore document IDs cannot contain forward slashes,
        so we replace them with tildes.

        Args:
            path: Original state path (e.g., "members/alice")

        Returns:
            Encoded path suitable for document ID (e.g., "members~alice")
        """
        return path.replace('/', '~')

    @staticmethod
    def _decode_path(encoded: str) -> str:
        """
        Decode Firestore document ID back to original path

        Args:
            encoded: Encoded document ID (e.g., "members~alice")

        Returns:
            Original path (e.g., "members/alice")
        """
        return encoded.replace('~', '/')

    def get_state(
        self,
        space_id: str,
        path: str
    ) -> Optional[Dict[str, Any]]:
        """Get state value by path from Firestore"""
        doc_id = self._encode_path(path)
        doc_ref = self.db.collection('spaces').document(space_id) \
                        .collection('state').document(doc_id)

        doc = doc_ref.get()
        if not doc.exists:
            return None

        data = doc.to_dict()
        return {
            'path': data['path'],
            'data': data['data'],
            'signature': data['signature'],
            'signed_by': data['signed_by'],
            'signed_at': data['signed_at']
        }

    def set_state(
        self,
        space_id: str,
        path: str,
        data: str,
        signature: str,
        signed_by: str,
        signed_at: int
    ) -> None:
        """Set state value in Firestore (signature required)"""
        doc_id = self._encode_path(path)
        doc_ref = self.db.collection('spaces').document(space_id) \
                        .collection('state').document(doc_id)

        doc_ref.set({
            'path': path,  # Keep original for querying
            'data': data,
            'signature': signature,
            'signed_by': signed_by,
            'signed_at': signed_at
        })

    def delete_state(self, space_id: str, path: str) -> bool:
        """Delete state value from Firestore"""
        doc_id = self._encode_path(path)
        doc_ref = self.db.collection('spaces').document(space_id) \
                        .collection('state').document(doc_id)

        doc = doc_ref.get()
        if doc.exists:
            doc_ref.delete()
            return True
        return False

    def list_state(
        self,
        space_id: str,
        prefix: str
    ) -> List[Dict[str, Any]]:
        """
        List all state entries matching a prefix (ordered by path)

        Uses Firestore range queries on the 'path' field to efficiently
        filter by prefix and maintain lexicographic ordering.
        """
        state_ref = self.db.collection('spaces').document(space_id) \
                          .collection('state')

        if prefix:
            # Prefix query: path >= prefix AND path < prefix + '\uffff'
            # This works because Firestore uses lexicographic ordering
            query = state_ref.where(filter=FieldFilter('path', '>=', prefix)) \
                            .where(filter=FieldFilter('path', '<', prefix + '\uffff')) \
                            .order_by('path')
        else:
            # No prefix: just order by path
            query = state_ref.order_by('path')

        results = []
        for doc in query.stream():
            data = doc.to_dict()
            results.append({
                'path': data['path'],
                'data': data['data'],
                'signature': data['signature'],
                'signed_by': data['signed_by'],
                'signed_at': data['signed_at']
            })

        return results

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
            space_id: Space ID
            tool_id: Tool ID (T_*)
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
                # Create new record
                transaction.set(doc_ref, {
                    'use_count': 1,
                    'last_used_at': timestamp
                })
                return 1

        transaction = self.db.transaction()
        return update_in_transaction(transaction, doc_ref)

    def get_tool_usage(self, space_id: str, tool_id: str) -> Optional[Dict[str, Any]]:
        """
        Get tool usage statistics from Firestore.

        This is operational metadata (NOT part of space state).

        Args:
            space_id: Space ID
            tool_id: Tool ID (T_*)

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
