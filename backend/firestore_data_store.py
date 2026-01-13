"""
Firestore implementation of DataStore for E2EE messaging system

Uses Google Cloud Firestore for legacy data persistence.
Supports multi-instance deployments with automatic consistency.

Note: This is the data storage system. New state storage should use
the event-sourced StateStore which stores state as messages in the message chain.
"""

from typing import Optional, List, Dict, Any
from google.cloud import firestore
from google.cloud.firestore_v1.base_query import FieldFilter
from data_store import DataStore


class FirestoreDataStore(DataStore):
    """Firestore-based legacy data storage implementation"""

    def __init__(self, project_id: Optional[str] = None, database_id: str = "(default)"):
        """
        Initialize Firestore data store

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
            path: Original data path (e.g., "members/alice")

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

    def get_data(
        self,
        space_id: str,
        path: str
    ) -> Optional[Dict[str, Any]]:
        """Get data value by path from Firestore"""
        doc_id = self._encode_path(path)
        doc_ref = self.db.collection('spaces').document(space_id) \
                        .collection('kv_data').document(doc_id)

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

    def set_data(
        self,
        space_id: str,
        path: str,
        data: str,
        signature: str,
        signed_by: str,
        signed_at: int
    ) -> None:
        """Set data value in Firestore (signature required)"""
        doc_id = self._encode_path(path)
        doc_ref = self.db.collection('spaces').document(space_id) \
                        .collection('kv_data').document(doc_id)

        doc_ref.set({
            'path': path,  # Keep original for querying
            'data': data,
            'signature': signature,
            'signed_by': signed_by,
            'signed_at': signed_at
        })

    def delete_data(self, space_id: str, path: str) -> bool:
        """Delete data value from Firestore"""
        doc_id = self._encode_path(path)
        doc_ref = self.db.collection('spaces').document(space_id) \
                        .collection('kv_data').document(doc_id)

        doc = doc_ref.get()
        if doc.exists:
            doc_ref.delete()
            return True
        return False

    def list_data(
        self,
        space_id: str,
        prefix: str
    ) -> List[Dict[str, Any]]:
        """
        List all data entries matching a prefix (ordered by path)

        Uses Firestore range queries on the 'path' field to efficiently
        filter by prefix and maintain lexicographic ordering.
        """
        data_ref = self.db.collection('spaces').document(space_id) \
                          .collection('kv_data')

        if prefix:
            # Prefix query: path >= prefix AND path < prefix + '\uffff'
            # This works because Firestore uses lexicographic ordering
            query = data_ref.where(filter=FieldFilter('path', '>=', prefix)) \
                            .where(filter=FieldFilter('path', '<', prefix + '\uffff')) \
                            .order_by('path')
        else:
            # No prefix: just order by path
            query = data_ref.order_by('path')

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
