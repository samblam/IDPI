"""
Streaming Router

Server-Sent Events (SSE) endpoint for real-time indicator updates
"""
import asyncio
import json
from datetime import datetime, timezone
from typing import Optional
from fastapi import APIRouter, Depends, Query, Request
from sse_starlette.sse import EventSourceResponse

from api.services.query_service import QueryService
from api.middleware.auth import get_api_key


router = APIRouter(prefix="/stream", tags=["Streaming"])
query_service = QueryService()


async def indicator_stream_generator(
    indicator_type: Optional[str] = None,
    confidence_min: Optional[int] = None,
    heartbeat_interval: int = 30
):
    """
    Generate SSE stream of indicator updates

    Sends heartbeats to keep connection alive

    Args:
        indicator_type: Filter by indicator type
        confidence_min: Minimum confidence score
        heartbeat_interval: Seconds between heartbeat messages
    """
    last_check = datetime.now(timezone.utc)
    last_heartbeat = datetime.now(timezone.utc)

    while True:
        try:
            # Send heartbeat if needed
            now = datetime.now(timezone.utc)
            if (now - last_heartbeat).total_seconds() >= heartbeat_interval:
                yield {
                    "event": "heartbeat",
                    "data": json.dumps({
                        "timestamp": now.isoformat(),
                        "status": "alive"
                    })
                }
                last_heartbeat = now

            # Query for new indicators
            result = await query_service.query_indicators(
                indicator_type=indicator_type,
                confidence_min=confidence_min,
                page_size=10
            )

            # Send new indicators
            for indicator in result["items"]:
                # Only send indicators updated since last check
                updated_at = indicator.get("updated_at", "")
                if updated_at >= last_check.isoformat():
                    yield {
                        "event": "indicator",
                        "data": json.dumps(indicator)
                    }

            last_check = now

            # Wait before next poll
            await asyncio.sleep(5)

        except asyncio.CancelledError:
            # Client disconnected
            yield {
                "event": "close",
                "data": json.dumps({"reason": "client_disconnect"})
            }
            break

        except Exception as e:
            # Send error and continue
            yield {
                "event": "error",
                "data": json.dumps({
                    "error": str(e),
                    "timestamp": datetime.now(timezone.utc).isoformat()
                })
            }
            await asyncio.sleep(5)


@router.get(
    "/indicators",
    summary="Stream indicator updates",
    description="Server-Sent Events stream of real-time indicator updates with heartbeats"
)
async def stream_indicators(
    request: Request,
    indicator_type: Optional[str] = Query(None, description="Filter by indicator type"),
    confidence_min: Optional[int] = Query(75, ge=0, le=100, description="Minimum confidence score"),
    heartbeat_interval: int = Query(30, ge=10, le=300, description="Heartbeat interval in seconds"),
    api_key_metadata: dict = Depends(get_api_key)
):
    """
    Stream indicator updates via Server-Sent Events

    Sends:
    - heartbeat events every N seconds to keep connection alive
    - indicator events when new indicators are detected
    - error events if issues occur

    Client should reconnect on close/error events.
    """
    return EventSourceResponse(
        indicator_stream_generator(
            indicator_type=indicator_type,
            confidence_min=confidence_min,
            heartbeat_interval=heartbeat_interval
        )
    )
