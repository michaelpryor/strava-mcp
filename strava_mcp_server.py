#!/usr/bin/env python3

import argparse
import asyncio
import contextlib
import json
import os
import secrets
from collections.abc import AsyncIterator
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

import httpx
import uvicorn
from mcp.server import NotificationOptions, Server
from mcp.server.models import InitializationOptions
from mcp.server.streamable_http_manager import StreamableHTTPSessionManager
from mcp.types import Resource, TextContent, Tool
from pydantic import AnyUrl
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route


class StravaAPI:
    def __init__(self, client_id: str, client_secret: str, refresh_token: str):
        self.client_id = client_id
        self.client_secret = client_secret
        self.refresh_token = refresh_token
        self.access_token: Optional[str] = None
        self.token_expires_at: Optional[datetime] = None

    async def refresh_access_token(self):
        """Refresh the access token using the refresh token"""
        async with httpx.AsyncClient() as client:
            response = await client.post(
                "https://www.strava.com/oauth/token",
                data={
                    "client_id": self.client_id,
                    "client_secret": self.client_secret,
                    "refresh_token": self.refresh_token,
                    "grant_type": "refresh_token"
                }
            )
            response.raise_for_status()
            token_data = response.json()
            
            self.access_token = token_data["access_token"]
            self.refresh_token = token_data["refresh_token"]
            expires_in = token_data["expires_in"]
            self.token_expires_at = datetime.now() + timedelta(seconds=expires_in)

    async def ensure_valid_token(self):
        """Ensure we have a valid access token"""
        if not self.access_token or (
            self.token_expires_at and datetime.now() >= self.token_expires_at - timedelta(minutes=5)
        ):
            await self.refresh_access_token()

    async def get_activities(self, before: Optional[int] = None, after: Optional[int] = None, per_page: int = 30) -> List[Dict[str, Any]]:
        """Get athlete activities"""
        await self.ensure_valid_token()
        
        params = {"per_page": per_page}
        if before:
            params["before"] = before
        if after:
            params["after"] = after

        async with httpx.AsyncClient() as client:
            response = await client.get(
                "https://www.strava.com/api/v3/athlete/activities",
                headers={"Authorization": f"Bearer {self.access_token}"},
                params=params
            )
            response.raise_for_status()
            return response.json()

    async def get_athlete(self) -> Dict[str, Any]:
        """Get athlete information"""
        await self.ensure_valid_token()
        
        async with httpx.AsyncClient() as client:
            response = await client.get(
                "https://www.strava.com/api/v3/athlete",
                headers={"Authorization": f"Bearer {self.access_token}"}
            )
            response.raise_for_status()
            return response.json()


def meters_to_miles(meters: float) -> float:
    """Convert meters to miles"""
    return meters * 0.000621371


def meters_per_second_to_pace(mps: float) -> str:
    """Convert meters per second to pace (min:sec per mile)"""
    if mps == 0:
        return "N/A"

    miles_per_second = mps * 0.000621371
    seconds_per_mile = 1 / miles_per_second
    minutes = int(seconds_per_mile // 60)
    seconds = int(seconds_per_mile % 60)
    return f"{minutes}:{seconds:02d}"


def meters_per_second_to_mph(mps: float) -> float:
    """Convert meters per second to miles per hour"""
    return mps * 2.23694


def meters_to_feet(meters: float) -> float:
    """Convert meters to feet"""
    return meters * 3.28084


app = Server("strava-coach")
strava_api: Optional[StravaAPI] = None


@app.list_tools()
async def handle_list_tools() -> List[Tool]:
    """List available tools"""
    return [
        Tool(
            name="get_recent_runs",
            description="Get recent running activities from Strava",
            inputSchema={
                "type": "object",
                "properties": {
                    "days": {
                        "type": "integer",
                        "description": "Number of days back to fetch activities (default: 30)",
                        "default": 30
                    },
                    "per_page": {
                        "type": "integer",
                        "description": "Max number of activities to fetch from Strava (default: 30, max: 200)",
                        "default": 30
                    }
                }
            }
        ),
        Tool(
            name="get_weekly_mileage",
            description="Calculate weekly mileage totals for recent weeks",
            inputSchema={
                "type": "object",
                "properties": {
                    "weeks": {
                        "type": "integer",
                        "description": "Number of weeks to analyze (default: 4)",
                        "default": 4
                    },
                    "per_page": {
                        "type": "integer",
                        "description": "Max number of activities to fetch from Strava (default: 30, max: 200)",
                        "default": 30
                    }
                }
            }
        ),
        Tool(
            name="analyze_pace_trends",
            description="Analyze pace trends over recent runs",
            inputSchema={
                "type": "object",
                "properties": {
                    "days": {
                        "type": "integer",
                        "description": "Number of days back to analyze (default: 30)",
                        "default": 30
                    },
                    "per_page": {
                        "type": "integer",
                        "description": "Max number of activities to fetch from Strava (default: 30, max: 200)",
                        "default": 30
                    }
                }
            }
        ),
        Tool(
            name="get_recent_rides",
            description="Get recent cycling activities from Strava with distance, speed, elevation, and power data",
            inputSchema={
                "type": "object",
                "properties": {
                    "days": {
                        "type": "integer",
                        "description": "Number of days back to fetch rides (default: 30)",
                        "default": 30
                    },
                    "per_page": {
                        "type": "integer",
                        "description": "Max number of activities to fetch from Strava (default: 30, max: 200)",
                        "default": 30
                    }
                }
            }
        ),
        Tool(
            name="get_weekly_ride_stats",
            description="Calculate weekly cycling distance, elevation gain, and ride time",
            inputSchema={
                "type": "object",
                "properties": {
                    "weeks": {
                        "type": "integer",
                        "description": "Number of weeks to analyze (default: 4)",
                        "default": 4
                    },
                    "per_page": {
                        "type": "integer",
                        "description": "Max number of activities to fetch from Strava (default: 30, max: 200)",
                        "default": 30
                    }
                }
            }
        ),
        Tool(
            name="analyze_ride_trends",
            description="Analyze cycling speed and power trends over recent rides",
            inputSchema={
                "type": "object",
                "properties": {
                    "days": {
                        "type": "integer",
                        "description": "Number of days back to analyze (default: 30)",
                        "default": 30
                    },
                    "per_page": {
                        "type": "integer",
                        "description": "Max number of activities to fetch from Strava (default: 30, max: 200)",
                        "default": 30
                    }
                }
            }
        )
    ]


@app.call_tool()
async def handle_call_tool(name: str, arguments: Dict[str, Any]) -> List[TextContent]:
    """Handle tool calls"""
    if not strava_api:
        return [TextContent(type="text", text="Strava API not initialized")]

    try:
        if name == "get_recent_runs":
            days = arguments.get("days", 30)
            per_page = arguments.get("per_page", 30)
            after_timestamp = int((datetime.now() - timedelta(days=days)).timestamp())

            activities = await strava_api.get_activities(after=after_timestamp, per_page=per_page)
            
            # Filter for running activities
            runs = [activity for activity in activities if activity["type"] == "Run"]
            
            if not runs:
                return [TextContent(type="text", text="No running activities found in the specified period.")]
            
            result = f"Found {len(runs)} running activities in the last {days} days:\n\n"
            
            for run in runs:
                date = datetime.fromisoformat(run["start_date_local"].replace("Z", "+00:00"))
                distance_miles = meters_to_miles(run["distance"])
                avg_pace = meters_per_second_to_pace(run["average_speed"]) if run["average_speed"] else "N/A"
                
                result += f"• {date.strftime('%Y-%m-%d')}: {run['name']}\n"
                result += f"  Distance: {distance_miles:.2f} miles\n"
                result += f"  Avg Pace: {avg_pace}/mile\n"
                result += f"  Duration: {run['elapsed_time'] // 60}:{run['elapsed_time'] % 60:02d}\n\n"
            
            return [TextContent(type="text", text=result)]

        elif name == "get_weekly_mileage":
            weeks = arguments.get("weeks", 4)
            per_page = arguments.get("per_page", 30)
            days_back = weeks * 7
            after_timestamp = int((datetime.now() - timedelta(days=days_back)).timestamp())

            activities = await strava_api.get_activities(after=after_timestamp, per_page=per_page)
            runs = [activity for activity in activities if activity["type"] == "Run"]
            
            # Group runs by week
            weekly_mileage = {}
            for run in runs:
                date = datetime.fromisoformat(run["start_date_local"].replace("Z", "+00:00"))
                week_start = date - timedelta(days=date.weekday())
                week_key = week_start.strftime("%Y-%m-%d")
                
                if week_key not in weekly_mileage:
                    weekly_mileage[week_key] = 0
                
                weekly_mileage[week_key] += meters_to_miles(run["distance"])
            
            if not weekly_mileage:
                return [TextContent(type="text", text="No running activities found for weekly mileage calculation.")]
            
            result = f"Weekly mileage for the last {weeks} weeks:\n\n"
            
            for week_start in sorted(weekly_mileage.keys(), reverse=True):
                result += f"Week of {week_start}: {weekly_mileage[week_start]:.1f} miles\n"
            
            total_mileage = sum(weekly_mileage.values())
            avg_weekly = total_mileage / len(weekly_mileage)
            result += f"\nTotal: {total_mileage:.1f} miles\n"
            result += f"Average per week: {avg_weekly:.1f} miles"
            
            return [TextContent(type="text", text=result)]

        elif name == "analyze_pace_trends":
            days = arguments.get("days", 30)
            per_page = arguments.get("per_page", 30)
            after_timestamp = int((datetime.now() - timedelta(days=days)).timestamp())

            activities = await strava_api.get_activities(after=after_timestamp, per_page=per_page)
            runs = [activity for activity in activities if activity["type"] == "Run" and activity["average_speed"]]
            
            if not runs:
                return [TextContent(type="text", text="No running activities with pace data found.")]
            
            # Sort by date
            runs.sort(key=lambda x: x["start_date_local"])
            
            result = f"Pace analysis for the last {days} days:\n\n"
            
            paces = []
            for run in runs:
                pace_seconds = 1 / (run["average_speed"] * 0.000621371)  # seconds per mile
                paces.append(pace_seconds)
                
                date = datetime.fromisoformat(run["start_date_local"].replace("Z", "+00:00"))
                pace_str = meters_per_second_to_pace(run["average_speed"])
                distance_miles = meters_to_miles(run["distance"])
                
                result += f"{date.strftime('%m/%d')}: {pace_str}/mile ({distance_miles:.1f}mi)\n"
            
            if len(paces) >= 2:
                avg_pace = sum(paces) / len(paces)
                avg_pace_str = f"{int(avg_pace // 60)}:{int(avg_pace % 60):02d}"
                
                recent_avg = sum(paces[-3:]) / min(3, len(paces))
                early_avg = sum(paces[:3]) / min(3, len(paces))
                
                trend = "improving" if recent_avg < early_avg else "declining"
                if abs(recent_avg - early_avg) < 10:  # within 10 seconds
                    trend = "stable"
                
                result += f"\nAverage pace: {avg_pace_str}/mile\n"
                result += f"Trend: {trend}"
            
            return [TextContent(type="text", text=result)]

        elif name == "get_recent_rides":
            days = arguments.get("days", 30)
            per_page = arguments.get("per_page", 30)
            after_timestamp = int((datetime.now() - timedelta(days=days)).timestamp())

            activities = await strava_api.get_activities(after=after_timestamp, per_page=per_page)
            rides = [a for a in activities if a["type"] == "Ride"]

            if not rides:
                return [TextContent(type="text", text="No cycling activities found in the specified period.")]

            result = f"Found {len(rides)} rides in the last {days} days:\n\n"

            for ride in rides:
                date = datetime.fromisoformat(ride["start_date_local"].replace("Z", "+00:00"))
                distance_miles = meters_to_miles(ride["distance"])
                avg_speed_mph = meters_per_second_to_mph(ride["average_speed"]) if ride.get("average_speed") else None
                elevation_ft = meters_to_feet(ride.get("total_elevation_gain", 0))
                duration_minutes = ride["elapsed_time"] // 60
                duration_seconds = ride["elapsed_time"] % 60

                result += f"• {date.strftime('%Y-%m-%d')}: {ride['name']}\n"
                result += f"  Distance: {distance_miles:.2f} miles\n"
                if avg_speed_mph is not None:
                    result += f"  Avg Speed: {avg_speed_mph:.1f} mph\n"
                result += f"  Elevation: {elevation_ft:.0f} ft\n"
                result += f"  Duration: {duration_minutes}:{duration_seconds:02d}\n"
                if ride.get("average_watts"):
                    result += f"  Avg Power: {ride['average_watts']:.0f}W\n"
                if ride.get("weighted_average_watts"):
                    result += f"  Normalized Power: {ride['weighted_average_watts']}W\n"
                if ride.get("kilojoules"):
                    result += f"  Energy: {ride['kilojoules']:.0f} kJ\n"
                result += "\n"

            return [TextContent(type="text", text=result)]

        elif name == "get_weekly_ride_stats":
            weeks = arguments.get("weeks", 4)
            per_page = arguments.get("per_page", 30)
            days_back = weeks * 7
            after_timestamp = int((datetime.now() - timedelta(days=days_back)).timestamp())

            activities = await strava_api.get_activities(after=after_timestamp, per_page=per_page)
            rides = [a for a in activities if a["type"] == "Ride"]

            weekly_stats: Dict[str, Dict[str, float]] = {}
            for ride in rides:
                date = datetime.fromisoformat(ride["start_date_local"].replace("Z", "+00:00"))
                week_start = date - timedelta(days=date.weekday())
                week_key = week_start.strftime("%Y-%m-%d")

                if week_key not in weekly_stats:
                    weekly_stats[week_key] = {"distance": 0, "elevation": 0, "time": 0, "rides": 0}

                weekly_stats[week_key]["distance"] += meters_to_miles(ride["distance"])
                weekly_stats[week_key]["elevation"] += meters_to_feet(ride.get("total_elevation_gain", 0))
                weekly_stats[week_key]["time"] += ride["elapsed_time"]
                weekly_stats[week_key]["rides"] += 1

            if not weekly_stats:
                return [TextContent(type="text", text="No cycling activities found for weekly stats.")]

            result = f"Weekly ride stats for the last {weeks} weeks:\n\n"

            for week_start in sorted(weekly_stats.keys(), reverse=True):
                stats = weekly_stats[week_start]
                hours = int(stats["time"] // 3600)
                minutes = int((stats["time"] % 3600) // 60)
                result += f"Week of {week_start}: {stats['rides']:.0f} rides, "
                result += f"{stats['distance']:.1f} mi, "
                result += f"{stats['elevation']:.0f} ft climbing, "
                result += f"{hours}h {minutes}m\n"

            total_distance = sum(s["distance"] for s in weekly_stats.values())
            total_elevation = sum(s["elevation"] for s in weekly_stats.values())
            total_rides = sum(s["rides"] for s in weekly_stats.values())
            result += f"\nTotal: {total_rides:.0f} rides, {total_distance:.1f} miles, {total_elevation:.0f} ft elevation\n"
            result += f"Average per week: {total_distance / len(weekly_stats):.1f} miles, {total_elevation / len(weekly_stats):.0f} ft"

            return [TextContent(type="text", text=result)]

        elif name == "analyze_ride_trends":
            days = arguments.get("days", 30)
            per_page = arguments.get("per_page", 30)
            after_timestamp = int((datetime.now() - timedelta(days=days)).timestamp())

            activities = await strava_api.get_activities(after=after_timestamp, per_page=per_page)
            rides = [a for a in activities if a["type"] == "Ride" and a.get("average_speed")]

            if not rides:
                return [TextContent(type="text", text="No cycling activities with speed data found.")]

            rides.sort(key=lambda x: x["start_date_local"])

            result = f"Ride trends for the last {days} days:\n\n"

            speeds = []
            powers = []
            for ride in rides:
                speed_mph = meters_per_second_to_mph(ride["average_speed"])
                speeds.append(speed_mph)

                date = datetime.fromisoformat(ride["start_date_local"].replace("Z", "+00:00"))
                distance_miles = meters_to_miles(ride["distance"])
                elevation_ft = meters_to_feet(ride.get("total_elevation_gain", 0))

                line = f"{date.strftime('%m/%d')}: {speed_mph:.1f} mph, {distance_miles:.1f} mi, {elevation_ft:.0f} ft"
                if ride.get("average_watts"):
                    powers.append(ride["average_watts"])
                    line += f", {ride['average_watts']:.0f}W"
                result += line + "\n"

            avg_speed = sum(speeds) / len(speeds)
            recent_speed_avg = sum(speeds[-3:]) / min(3, len(speeds))
            early_speed_avg = sum(speeds[:3]) / min(3, len(speeds))

            speed_trend = "improving" if recent_speed_avg > early_speed_avg else "declining"
            if abs(recent_speed_avg - early_speed_avg) < 0.5:
                speed_trend = "stable"

            result += f"\nAvg speed: {avg_speed:.1f} mph\n"
            result += f"Speed trend: {speed_trend}"

            if powers:
                avg_power = sum(powers) / len(powers)
                result += f"\nAvg power: {avg_power:.0f}W"
                if len(powers) >= 3:
                    recent_power_avg = sum(powers[-3:]) / min(3, len(powers))
                    early_power_avg = sum(powers[:3]) / min(3, len(powers))
                    power_trend = "improving" if recent_power_avg > early_power_avg else "declining"
                    if abs(recent_power_avg - early_power_avg) < 5:
                        power_trend = "stable"
                    result += f"\nPower trend: {power_trend}"

            return [TextContent(type="text", text=result)]

        else:
            return [TextContent(type="text", text=f"Unknown tool: {name}")]

    except Exception as e:
        return [TextContent(type="text", text=f"Error: {str(e)}")]


def init_strava_api():
    """Initialize the Strava API client from environment variables"""
    global strava_api

    client_id = os.getenv("STRAVA_CLIENT_ID")
    client_secret = os.getenv("STRAVA_CLIENT_SECRET")
    refresh_token = os.getenv("STRAVA_REFRESH_TOKEN")

    if not all([client_id, client_secret, refresh_token]):
        raise ValueError(
            "Missing required environment variables: STRAVA_CLIENT_ID, STRAVA_CLIENT_SECRET, STRAVA_REFRESH_TOKEN"
        )

    strava_api = StravaAPI(client_id, client_secret, refresh_token)


def create_http_app() -> Starlette:
    """Create a Starlette app with Streamable HTTP transport and bearer token auth"""
    auth_token = os.getenv("MCP_AUTH_TOKEN")
    if not auth_token:
        raise ValueError(
            "MCP_AUTH_TOKEN environment variable is required for HTTP transport"
        )

    session_manager = StreamableHTTPSessionManager(app=app)

    async def authenticate(request: Request) -> Optional[Response]:
        auth_header = request.headers.get("authorization", "")
        if not auth_header.startswith("Bearer "):
            return JSONResponse({"error": "Missing bearer token"}, status_code=401)
        token = auth_header[len("Bearer "):]
        if not secrets.compare_digest(token, auth_token):
            return JSONResponse({"error": "Invalid token"}, status_code=403)
        return None

    async def handle_mcp(request: Request) -> Response:
        auth_error = await authenticate(request)
        if auth_error:
            return auth_error
        await session_manager.handle_request(
            request.scope, request.receive, request._send
        )
        return Response()

    async def handle_health(request: Request) -> Response:
        return JSONResponse({"status": "ok", "server": "strava-coach"})

    @contextlib.asynccontextmanager
    async def lifespan(starlette_app: Starlette) -> AsyncIterator[None]:
        async with session_manager.run():
            yield

    return Starlette(
        routes=[
            Route("/mcp", endpoint=handle_mcp, methods=["GET", "POST", "DELETE"]),
            Route("/health", endpoint=handle_health, methods=["GET"]),
        ],
        lifespan=lifespan,
    )


async def run_stdio():
    """Run the server with stdio transport (local use)"""
    from mcp.server.stdio import stdio_server

    async with stdio_server() as (read_stream, write_stream):
        await app.run(
            read_stream,
            write_stream,
            InitializationOptions(
                server_name="strava-coach",
                server_version="1.0.0",
                capabilities=app.get_capabilities(
                    notification_options=NotificationOptions(),
                    experimental_capabilities={},
                ),
            ),
        )


def main():
    parser = argparse.ArgumentParser(description="Strava MCP Server")
    parser.add_argument(
        "--transport",
        choices=["stdio", "http"],
        default="stdio",
        help="Transport mode: stdio (local) or http (remote, default: stdio)",
    )
    parser.add_argument(
        "--host", default="0.0.0.0", help="Host to bind to (http mode, default: 0.0.0.0)"
    )
    parser.add_argument(
        "--port",
        type=int,
        default=int(os.getenv("PORT", "8000")),
        help="Port to listen on (http mode, default: PORT env or 8000)",
    )
    args = parser.parse_args()

    init_strava_api()

    if args.transport == "http":
        http_app = create_http_app()
        uvicorn.run(http_app, host=args.host, port=args.port)
    else:
        asyncio.run(run_stdio())


if __name__ == "__main__":
    main()