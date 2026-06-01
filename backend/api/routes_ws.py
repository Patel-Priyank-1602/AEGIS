"""
AEGIS WebSocket API
Streams real-time threat events to connected dashboard clients.
Supports multiple simultaneous dashboard connections.
"""

from fastapi import APIRouter, WebSocket, WebSocketDisconnect
import asyncio
import json

router = APIRouter()

# ─── Broadcast system: each client gets its own queue ───────────
connected_clients: dict[WebSocket, asyncio.Queue] = {}


async def broadcast_event(event: dict):
    """Send an event to ALL connected dashboard clients."""
    dead_clients = []
    for ws, queue in connected_clients.items():
        try:
            await queue.put(event)
        except Exception:
            dead_clients.append(ws)

    for ws in dead_clients:
        connected_clients.pop(ws, None)


@router.websocket("/ws/events")
async def websocket_events(ws: WebSocket):
    """
    WebSocket endpoint for real-time event streaming.

    Each connected dashboard gets its own queue so ALL clients
    receive ALL events (fan-out broadcast pattern).
    """
    await ws.accept()

    # Give this client its own queue
    client_queue: asyncio.Queue = asyncio.Queue(maxsize=500)
    connected_clients[ws] = client_queue
    print(f"[WS] Dashboard connected. Total clients: {len(connected_clients)}")

    try:
        # Heartbeat task to keep connection alive
        async def heartbeat():
            while True:
                await asyncio.sleep(15)
                try:
                    await ws.send_text(json.dumps({"type": "heartbeat"}))
                except Exception:
                    break

        hb_task = asyncio.create_task(heartbeat())

        # Receive task to handle client messages (keeps WS alive)
        async def receive_messages():
            try:
                while True:
                    await ws.receive_text()
            except WebSocketDisconnect:
                pass
            except Exception:
                pass

        recv_task = asyncio.create_task(receive_messages())

        # Main loop: forward events from this client's queue
        while True:
            try:
                event = await asyncio.wait_for(client_queue.get(), timeout=30)
                await ws.send_text(json.dumps(event))
            except asyncio.TimeoutError:
                # No events for 30s, send keepalive
                try:
                    await ws.send_text(json.dumps({"type": "heartbeat"}))
                except Exception:
                    break
            except Exception:
                break

    except WebSocketDisconnect:
        pass
    except Exception as e:
        print(f"[WS] Client error: {e}")
    finally:
        connected_clients.pop(ws, None)
        hb_task.cancel()
        recv_task.cancel()
        print(f"[WS] Dashboard disconnected. Total clients: {len(connected_clients)}")


@router.websocket("/ws/status")
async def websocket_status(ws: WebSocket):
    """Lightweight WebSocket for system status updates."""
    await ws.accept()
    try:
        while True:
            status = {
                "type": "status",
                "connected_dashboards": len(connected_clients),
            }
            await ws.send_text(json.dumps(status))
            await asyncio.sleep(5)
    except WebSocketDisconnect:
        pass
