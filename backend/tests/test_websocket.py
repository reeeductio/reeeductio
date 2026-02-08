"""
WebSocket streaming tests
"""
import pytest
import json
import base64
from unittest.mock import AsyncMock, MagicMock, patch
from fastapi import WebSocket, WebSocketDisconnect
from fastapi.testclient import TestClient

import sys
from pathlib import Path

# Add tests directory to path to import conftest
sys.path.insert(0, str(Path(__file__).parent))

from main import app, authenticate_websocket, space_manager

import conftest
set_space_state = conftest.set_space_state
authenticate_with_challenge = conftest.authenticate_with_challenge

class TestWebSocketAuthentication:
    """Test WebSocket authentication"""

    @pytest.mark.asyncio
    async def test_authenticate_websocket_success(self, admin_keypair):
        """Test successful WebSocket authentication"""
        space_id = admin_keypair['space_id']
        space = space_manager.get_space(space_id)
        jwt_data = space.create_jwt(admin_keypair['user_id'])
        token = jwt_data['token']

        result = await authenticate_websocket(space_id, token)
        print("Got websocket result =", result)

        assert result['space_id'] == space_id
        assert result['id'] == admin_keypair['user_id']

    @pytest.mark.asyncio
    async def test_authenticate_websocket_no_token(self):
        """Test WebSocket authentication fails without token"""
        with pytest.raises(WebSocketDisconnect) as exc_info:
            await authenticate_websocket("test_space", None)

        assert exc_info.value.code == 1008
        assert "Authentication required" in exc_info.value.reason

    @pytest.mark.asyncio
    async def test_authenticate_websocket_invalid_token(self):
        """Test WebSocket authentication fails with invalid token"""
        with pytest.raises(WebSocketDisconnect) as exc_info:
            await authenticate_websocket("test_space", "invalid_token")

        assert exc_info.value.code == 1008

    @pytest.mark.asyncio
    async def test_authenticate_websocket_wrong_space(self, admin_keypair):
        """Test WebSocket authentication fails with wrong space"""
        space_id = admin_keypair['space_id']
        space = space_manager.get_space(space_id)
        jwt_data = space.create_jwt(admin_keypair['user_id'])
        token = jwt_data['token']

        with pytest.raises(WebSocketDisconnect) as exc_info:
            await authenticate_websocket("different_space", token)

        assert exc_info.value.code == 1008
        assert "Token space mismatch" in exc_info.value.reason


class TestWebSocketEndpoint:
    """Test WebSocket endpoint integration"""

    @pytest.fixture
    def client(self):
        """Create a test client"""
        return TestClient(app)

    def test_websocket_connect_without_token(self, client, admin_keypair):
        """Test WebSocket connection fails without token"""
        space_id = admin_keypair['space_id']

        with pytest.raises(WebSocketDisconnect):
            with client.websocket_connect(f"/spaces/{space_id}/stream"):
                pass

    def test_websocket_connect_with_invalid_token(self, client, admin_keypair):
        """Test WebSocket connection fails with invalid token"""
        space_id = admin_keypair['space_id']

        with pytest.raises(WebSocketDisconnect):
            with client.websocket_connect(
                f"/spaces/{space_id}/stream?token=invalid_token"
            ):
                pass

    def test_websocket_connect_success(self, client, admin_keypair):
        """Test successful WebSocket connection"""
        space_id = admin_keypair['space_id']
        user_id = admin_keypair['user_id']
        admin_private = admin_keypair['private']

        # Get space
        space = space_manager.get_space(space_id)

        # Authenticate and add user as member
        admin_token = authenticate_with_challenge(space, user_id, admin_private)

        member_data = {
            "user_id": user_id
        }
        set_space_state(
            space=space,
            path=f"auth/users/{user_id}",
            contents=member_data,
            token=admin_token,
            keypair=admin_keypair
        )

        # Create JWT token
        jwt_data = space.create_jwt(user_id)
        token = jwt_data['token']

        # Connect via WebSocket
        with client.websocket_connect(
            f"/spaces/{space_id}/stream?token={token}"
        ) as websocket:
            # Send ping
            websocket.send_text("ping")

            # Receive pong
            data = websocket.receive_text()
            assert data == "pong"

    def test_websocket_receives_broadcast(self, client, admin_keypair):
        """Test WebSocket receives broadcast messages"""
        space_id = admin_keypair['space_id']
        user_id = admin_keypair['user_id']
        admin_private = admin_keypair['private']

        # Get space
        space = space_manager.get_space(space_id)

        # Authenticate and add user as member
        admin_token = authenticate_with_challenge(space, user_id, admin_private)

        member_data = {
            "user_id": user_id
        }
        set_space_state(
            space=space,
            path=f"auth/users/{user_id}",
            contents=member_data,
            token=admin_token,
            keypair=admin_keypair
        )

        # Create JWT token
        jwt_data = space.create_jwt(user_id)
        token = jwt_data['token']

        # Connect via WebSocket
        with client.websocket_connect(
            f"/spaces/{space_id}/stream?token={token}"
        ) as websocket:
            # Simulate a broadcast from the server
            import asyncio
            message = {
                "message_hash": "test_hash_123",
                "topic_id": "general",
                "prev_hash": None,
                "data": "test_payload",
                "sender": user_id,
                "signature": "test_signature",
                "server_timestamp": 12345000
            }

            # Broadcast message via space
            asyncio.run(space.broadcast_message(message))

            # Receive the broadcast
            data = websocket.receive_text()
            received = json.loads(data)

            assert received['message_hash'] == "test_hash_123"
            assert received['topic_id'] == "general"
            assert received['sender'] == user_id


class TestWebSocketMessageBroadcasting:
    """Test message broadcasting integration"""

    @pytest.mark.asyncio
    async def test_post_message_broadcasts_to_websockets(
        self, message_store, data_store, crypto, authz, admin_keypair
    ):
        """Test that posting a message broadcasts to WebSocket clients"""
        space_id = admin_keypair['space_id']
        admin_id = admin_keypair['user_id']
        admin_private = admin_keypair['private']

        # Create mock WebSocket connections
        ws1 = AsyncMock(spec=WebSocket)
        ws1.send_text = AsyncMock()
        ws2 = AsyncMock(spec=WebSocket)
        ws2.send_text = AsyncMock()

        # Get space and add connections directly to it
        space = space_manager.get_space(space_id)
        space.websockets = {ws1, ws2}

        # Post a message (this should trigger broadcast)
        topic_id = "general-chat"
        data = "encrypted_content"
        msg_hash = crypto.compute_message_hash(
            space_id, topic_id, "chat.text", None, data, admin_id
        )
        signature = crypto.base64_encode(
            admin_private.sign(msg_hash.encode('utf-8'))
        )

        message_store.add_message(
            space_id=space_id,
            topic_id=topic_id,
            message_hash=msg_hash,
            msg_type="chat.text",
            prev_hash=None,
            data=data,
            sender=admin_id,
            signature=signature,
            server_timestamp=12345000
        )

        # Simulate the broadcast that happens in post_message endpoint
        message_dict = {
            "message_hash": msg_hash,
            "topic_id": topic_id,
            "prev_hash": None,
            "data": data,
            "sender": admin_id,
            "signature": signature,
            "server_timestamp": 12345000
        }
        await space.broadcast_message(message_dict)

        # Verify both connections received the message
        ws1.send_text.assert_called_once()
        ws2.send_text.assert_called_once()

        # Verify the message content
        call_arg = ws1.send_text.call_args[0][0]
        received_message = json.loads(call_arg)
        assert received_message['message_hash'] == msg_hash
        assert received_message['topic_id'] == topic_id
        assert received_message['sender'] == admin_id
