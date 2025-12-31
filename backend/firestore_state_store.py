"""
Firestore implementation of StateStore for E2EE messaging system

Uses Google Cloud Firestore (in Datastore mode) for state persistence.
Supports multi-instance deployments with automatic consistency.
"""

from typing import Optional, List, Dict, Any
from google.cloud import firestore
from state_store import StateStore


class FirestoreStateStore(StateStore):
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
        channel_id: str,
        path: str
    ) -> Optional[Dict[str, Any]]:
        """Get state value by path from Firestore"""
        doc_id = self._encode_path(path)
        doc_ref = self.db.collection('channels').document(channel_id) \
                        .collection('state').document(doc_id)

        doc = doc_ref.get()
        if not doc.exists:
            return None

        data = doc.to_dict()
        return {
            'data': data['data'],
            'updated_by': data['updated_by'],
            'updated_at': data['updated_at']
        }

    def set_state(
        self,
        channel_id: str,
        path: str,
        data: str,
        updated_by: str,
        updated_at: int
    ) -> None:
        """Set state value in Firestore"""
        doc_id = self._encode_path(path)
        doc_ref = self.db.collection('channels').document(channel_id) \
                        .collection('state').document(doc_id)

        doc_ref.set({
            'path': path,  # Keep original for querying
            'data': data,
            'updated_by': updated_by,
            'updated_at': updated_at
        })

    def delete_state(self, channel_id: str, path: str) -> bool:
        """Delete state value from Firestore"""
        doc_id = self._encode_path(path)
        doc_ref = self.db.collection('channels').document(channel_id) \
                        .collection('state').document(doc_id)

        doc = doc_ref.get()
        if doc.exists:
            doc_ref.delete()
            return True
        return False

    def list_state(
        self,
        channel_id: str,
        prefix: str
    ) -> List[Dict[str, Any]]:
        """
        List all state entries matching a prefix (ordered by path)

        Uses Firestore range queries on the 'path' field to efficiently
        filter by prefix and maintain lexicographic ordering.
        """
        state_ref = self.db.collection('channels').document(channel_id) \
                          .collection('state')

        if prefix:
            # Prefix query: path >= prefix AND path < prefix + '\uffff'
            # This works because Firestore uses lexicographic ordering
            query = state_ref.where('path', '>=', prefix) \
                            .where('path', '<', prefix + '\uffff') \
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
                'updated_by': data['updated_by'],
                'updated_at': data['updated_at']
            })

        return results
