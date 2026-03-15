#!/usr/bin/env python3

import argparse
import asyncio
import base64
import contextlib
import hashlib
import hmac
import json
import os
import secrets
import time
from collections.abc import AsyncIterator
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional
from urllib.parse import urlencode

import httpx
import uvicorn
from mcp.server import NotificationOptions, Server
from mcp.server.models import InitializationOptions
from mcp.server.streamable_http_manager import StreamableHTTPSessionManager
from mcp.types import Resource, TextContent, Tool
from pydantic import AnyUrl
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
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
        """Get athlete activities, paginating through all results."""
        await self.ensure_valid_token()

        all_activities: List[Dict[str, Any]] = []
        page = 1
        page_size = min(per_page, 200)

        async with httpx.AsyncClient() as client:
            while True:
                params: Dict[str, Any] = {"per_page": page_size, "page": page}
                if before:
                    params["before"] = before
                if after:
                    params["after"] = after

                response = await client.get(
                    "https://www.strava.com/api/v3/athlete/activities",
                    headers={"Authorization": f"Bearer {self.access_token}"},
                    params=params
                )
                response.raise_for_status()
                batch = response.json()

                if not batch:
                    break

                all_activities.extend(batch)

                # If caller specified a limit via per_page, stop once we have enough
                if len(all_activities) >= per_page:
                    all_activities = all_activities[:per_page]
                    break

                # Partial page means no more results
                if len(batch) < page_size:
                    break

                page += 1

        return all_activities

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


class SimpleOAuthProvider:
    """OAuth 2.0 provider for single-user MCP server.

    Uses HMAC-signed tokens so access/refresh tokens survive server restarts.
    Only auth codes and pending sessions are in-memory (short-lived).
    """

    def __init__(self, password: str):
        self.password = password
        self.signing_key = password
        self.clients: Dict[str, Dict[str, Any]] = {}
        self.auth_codes: Dict[str, Dict[str, Any]] = {}
        self.pending_auth: Dict[str, Dict[str, Any]] = {}

    def _sign_token(self, payload: Dict[str, Any]) -> str:
        payload_json = json.dumps(payload, separators=(",", ":"), sort_keys=True)
        payload_b64 = base64.urlsafe_b64encode(payload_json.encode()).decode().rstrip("=")
        sig = hmac.new(
            self.signing_key.encode(), payload_b64.encode(), hashlib.sha256
        ).hexdigest()
        return f"{payload_b64}.{sig}"

    def _verify_token(self, token: str) -> Optional[Dict[str, Any]]:
        try:
            payload_b64, sig = token.rsplit(".", 1)
            expected_sig = hmac.new(
                self.signing_key.encode(), payload_b64.encode(), hashlib.sha256
            ).hexdigest()
            if not hmac.compare_digest(sig, expected_sig):
                return None
            padding = 4 - len(payload_b64) % 4
            if padding != 4:
                payload_b64 += "=" * padding
            payload = json.loads(base64.urlsafe_b64decode(payload_b64))
            if payload.get("exp", 0) < time.time():
                return None
            return payload
        except Exception:
            return None

    def register_client(self, metadata: Dict[str, Any]) -> Dict[str, Any]:
        client_id = secrets.token_urlsafe(16)
        client_secret = secrets.token_urlsafe(32)
        client = {
            **metadata,
            "client_id": client_id,
            "client_secret": client_secret,
            "client_id_issued_at": int(time.time()),
        }
        self.clients[client_id] = client
        return client

    def start_authorize(
        self,
        client_id: str,
        code_challenge: str,
        redirect_uri: str,
        state: Optional[str],
        scopes: List[str],
    ) -> str:
        session_id = secrets.token_urlsafe(32)
        self.pending_auth[session_id] = {
            "client_id": client_id,
            "code_challenge": code_challenge,
            "redirect_uri": redirect_uri,
            "state": state,
            "scopes": scopes,
        }
        return session_id

    def complete_authorize(self, session_id: str) -> Optional[tuple]:
        pending = self.pending_auth.pop(session_id, None)
        if not pending:
            return None
        code = secrets.token_urlsafe(32)
        self.auth_codes[code] = {
            **pending,
            "expires_at": time.time() + 300,
        }
        return code, pending["redirect_uri"], pending["state"]

    def exchange_code(
        self, code: str, client_id: str, code_verifier: str, redirect_uri: str
    ) -> tuple:
        auth_code = self.auth_codes.pop(code, None)
        if not auth_code:
            return None, "invalid_grant"
        if auth_code["expires_at"] < time.time():
            return None, "invalid_grant"
        if auth_code["client_id"] != client_id:
            return None, "invalid_grant"
        if auth_code["redirect_uri"] != redirect_uri:
            return None, "invalid_grant"
        # Verify PKCE (S256)
        expected = (
            base64.urlsafe_b64encode(hashlib.sha256(code_verifier.encode()).digest())
            .rstrip(b"=")
            .decode()
        )
        if expected != auth_code["code_challenge"]:
            return None, "invalid_grant"
        return self._issue_tokens(client_id, auth_code["scopes"]), None

    def refresh(self, refresh_token_str: str, client_id: str) -> tuple:
        payload = self._verify_token(refresh_token_str)
        if not payload:
            return None, "invalid_grant"
        if payload.get("type") != "refresh":
            return None, "invalid_grant"
        return self._issue_tokens(client_id, payload.get("scopes", [])), None

    def validate_token(self, token: str) -> Optional[Dict[str, Any]]:
        payload = self._verify_token(token)
        if not payload:
            return None
        if payload.get("type") != "access":
            return None
        return payload

    def _issue_tokens(self, client_id: str, scopes: List[str]) -> Dict[str, Any]:
        access_payload = {
            "type": "access",
            "client_id": client_id,
            "scopes": scopes,
            "exp": int(time.time()) + 86400,
        }
        refresh_payload = {
            "type": "refresh",
            "client_id": client_id,
            "scopes": scopes,
            "exp": int(time.time()) + 86400 * 30,
        }
        result: Dict[str, Any] = {
            "access_token": self._sign_token(access_payload),
            "token_type": "bearer",
            "expires_in": 86400,
            "refresh_token": self._sign_token(refresh_payload),
        }
        if scopes:
            result["scope"] = " ".join(scopes)
        return result


LOGIN_PAGE_HTML = """<!DOCTYPE html>
<html>
<head>
    <title>Strava MCP - Authorize</title>
    <style>
        body {{ font-family: system-ui, sans-serif; max-width: 400px; margin: 80px auto; padding: 0 20px; }}
        h2 {{ color: #333; }}
        input[type="password"] {{ width: 100%; padding: 10px; margin: 10px 0; box-sizing: border-box; border: 1px solid #ccc; border-radius: 4px; }}
        button {{ background: #fc4c02; color: white; border: none; padding: 10px 24px; border-radius: 4px; cursor: pointer; font-size: 16px; }}
        button:hover {{ background: #e04400; }}
        .error {{ color: #c00; }}
    </style>
</head>
<body>
    <h2>Authorize MCP Access</h2>
    <p>Enter your server password to grant access to your Strava data.</p>
    {error}
    <form method="POST" action="/login">
        <input type="hidden" name="session" value="{session_id}">
        <input type="password" name="password" placeholder="Server password" required autofocus>
        <button type="submit">Authorize</button>
    </form>
</body>
</html>"""


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
                moving_minutes = ride.get("moving_time", ride["elapsed_time"]) // 60
                moving_seconds = ride.get("moving_time", ride["elapsed_time"]) % 60
                elapsed_minutes = ride["elapsed_time"] // 60
                elapsed_seconds = ride["elapsed_time"] % 60
                is_indoor = ride.get("trainer", False)

                result += f"• {date.strftime('%Y-%m-%d')}: {ride['name']}"
                if is_indoor:
                    result += " (indoor/trainer)"
                result += "\n"
                if distance_miles > 0:
                    result += f"  Distance: {distance_miles:.2f} miles\n"
                if avg_speed_mph and avg_speed_mph > 0:
                    result += f"  Avg Speed: {avg_speed_mph:.1f} mph\n"
                if ride.get("max_speed") and ride["max_speed"] > 0:
                    result += f"  Max Speed: {meters_per_second_to_mph(ride['max_speed']):.1f} mph\n"
                if elevation_ft > 0:
                    result += f"  Elevation: {elevation_ft:.0f} ft\n"
                result += f"  Moving Time: {moving_minutes}:{moving_seconds:02d}\n"
                if moving_minutes != elapsed_minutes or moving_seconds != elapsed_seconds:
                    result += f"  Elapsed Time: {elapsed_minutes}:{elapsed_seconds:02d}\n"
                if ride.get("average_watts"):
                    result += f"  Avg Power: {ride['average_watts']:.0f}W\n"
                if ride.get("weighted_average_watts"):
                    result += f"  Normalized Power: {ride['weighted_average_watts']}W\n"
                if ride.get("kilojoules"):
                    result += f"  Energy: {ride['kilojoules']:.0f} kJ\n"
                if ride.get("has_heartrate"):
                    result += f"  Avg Heart Rate: {ride['average_heartrate']:.0f} bpm\n"
                    result += f"  Max Heart Rate: {ride['max_heartrate']:.0f} bpm\n"
                if ride.get("suffer_score"):
                    result += f"  Relative Effort: {ride['suffer_score']:.0f}\n"
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
            rides = [a for a in activities if a["type"] == "Ride"]

            if not rides:
                return [TextContent(type="text", text="No cycling activities found.")]

            rides.sort(key=lambda x: x["start_date_local"])

            result = f"Ride trends for the last {days} days:\n\n"

            speeds = []
            powers = []
            heart_rates = []
            efforts = []
            for ride in rides:
                date = datetime.fromisoformat(ride["start_date_local"].replace("Z", "+00:00"))
                moving_min = ride.get("moving_time", ride["elapsed_time"]) // 60
                is_indoor = ride.get("trainer", False)

                line = f"{date.strftime('%m/%d')}: {moving_min}min"
                if is_indoor:
                    line += " (indoor)"

                if ride.get("average_speed") and ride["average_speed"] > 0:
                    speed_mph = meters_per_second_to_mph(ride["average_speed"])
                    speeds.append(speed_mph)
                    distance_miles = meters_to_miles(ride["distance"])
                    line += f", {speed_mph:.1f} mph, {distance_miles:.1f} mi"

                if ride.get("total_elevation_gain") and ride["total_elevation_gain"] > 0:
                    line += f", {meters_to_feet(ride['total_elevation_gain']):.0f} ft"

                if ride.get("average_watts"):
                    powers.append(ride["average_watts"])
                    line += f", {ride['average_watts']:.0f}W"

                if ride.get("has_heartrate"):
                    heart_rates.append(ride["average_heartrate"])
                    line += f", {ride['average_heartrate']:.0f} bpm avg HR"

                if ride.get("suffer_score"):
                    efforts.append(ride["suffer_score"])
                    line += f", effort {ride['suffer_score']:.0f}"

                result += line + "\n"

            result += "\n--- Summary ---\n"

            if speeds:
                avg_speed = sum(speeds) / len(speeds)
                result += f"Avg speed: {avg_speed:.1f} mph\n"
                if len(speeds) >= 3:
                    recent = sum(speeds[-3:]) / 3
                    early = sum(speeds[:3]) / 3
                    trend = "improving" if recent > early else ("stable" if abs(recent - early) < 0.5 else "declining")
                    result += f"Speed trend: {trend}\n"

            if powers:
                avg_power = sum(powers) / len(powers)
                result += f"Avg power: {avg_power:.0f}W\n"
                if len(powers) >= 3:
                    recent = sum(powers[-3:]) / 3
                    early = sum(powers[:3]) / 3
                    trend = "improving" if recent > early else ("stable" if abs(recent - early) < 5 else "declining")
                    result += f"Power trend: {trend}\n"

            if heart_rates:
                avg_hr = sum(heart_rates) / len(heart_rates)
                result += f"Avg heart rate: {avg_hr:.0f} bpm\n"
                if len(heart_rates) >= 3:
                    recent = sum(heart_rates[-3:]) / 3
                    early = sum(heart_rates[:3]) / 3
                    # Lower HR at same effort = improving fitness
                    trend = "improving (lower HR)" if recent < early else ("stable" if abs(recent - early) < 3 else "higher HR")
                    result += f"HR trend: {trend}\n"

            if efforts:
                avg_effort = sum(efforts) / len(efforts)
                result += f"Avg relative effort: {avg_effort:.0f}\n"

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
    """Create a Starlette app with OAuth 2.0 authentication for remote MCP access."""
    auth_token = os.getenv("MCP_AUTH_TOKEN")
    if not auth_token:
        raise ValueError(
            "MCP_AUTH_TOKEN environment variable is required for HTTP transport"
        )

    oauth = SimpleOAuthProvider(auth_token)
    session_manager = StreamableHTTPSessionManager(app=app)

    async def handle_oauth_metadata(request: Request) -> Response:
        server_url = str(request.base_url).rstrip("/")
        return JSONResponse({
            "issuer": server_url,
            "authorization_endpoint": f"{server_url}/authorize",
            "token_endpoint": f"{server_url}/token",
            "registration_endpoint": f"{server_url}/register",
            "response_types_supported": ["code"],
            "grant_types_supported": ["authorization_code", "refresh_token"],
            "token_endpoint_auth_methods_supported": ["client_secret_post", "none"],
            "code_challenge_methods_supported": ["S256"],
        })

    async def handle_protected_resource_metadata(request: Request) -> Response:
        server_url = str(request.base_url).rstrip("/")
        return JSONResponse({
            "resource": server_url,
            "authorization_servers": [server_url],
            "bearer_methods_supported": ["header"],
        })

    async def handle_register(request: Request) -> Response:
        if request.method == "GET":
            return JSONResponse({
                "registration_endpoint": f"{str(request.base_url).rstrip('/')}/register",
                "registration_endpoint_auth_methods_supported": [],
            })
        body = await request.json()
        client = oauth.register_client(body)
        return JSONResponse(client, status_code=201)

    async def handle_authorize(request: Request) -> Response:
        client_id = request.query_params.get("client_id", "")
        if not client_id or client_id not in oauth.clients:
            return JSONResponse({"error": "invalid_client"}, status_code=400)
        session_id = oauth.start_authorize(
            client_id=client_id,
            code_challenge=request.query_params.get("code_challenge", ""),
            redirect_uri=request.query_params.get("redirect_uri", ""),
            state=request.query_params.get("state"),
            scopes=(
                request.query_params.get("scope", "").split()
                if request.query_params.get("scope")
                else []
            ),
        )
        return RedirectResponse(f"/login?session={session_id}")

    async def handle_login(request: Request) -> Response:
        if request.method == "GET":
            session_id = request.query_params.get("session", "")
            return HTMLResponse(
                LOGIN_PAGE_HTML.format(session_id=session_id, error="")
            )
        form = await request.form()
        session_id = str(form.get("session", ""))
        password = str(form.get("password", ""))
        if not secrets.compare_digest(password, auth_token):
            return HTMLResponse(
                LOGIN_PAGE_HTML.format(
                    session_id=session_id,
                    error='<p class="error">Invalid password. Please try again.</p>',
                ),
                status_code=403,
            )
        result = oauth.complete_authorize(session_id)
        if not result:
            return HTMLResponse("Invalid or expired session.", status_code=400)
        code, redirect_uri, state = result
        params: Dict[str, str] = {"code": code}
        if state:
            params["state"] = state
        return RedirectResponse(
            f"{redirect_uri}?{urlencode(params)}", status_code=302
        )

    async def handle_token(request: Request) -> Response:
        form = await request.form()
        grant_type = form.get("grant_type")
        client_id = str(form.get("client_id", ""))
        if grant_type == "authorization_code":
            tokens, error = oauth.exchange_code(
                code=str(form.get("code", "")),
                client_id=client_id,
                code_verifier=str(form.get("code_verifier", "")),
                redirect_uri=str(form.get("redirect_uri", "")),
            )
        elif grant_type == "refresh_token":
            tokens, error = oauth.refresh(
                refresh_token_str=str(form.get("refresh_token", "")),
                client_id=client_id,
            )
        else:
            return JSONResponse(
                {"error": "unsupported_grant_type"}, status_code=400
            )
        if error:
            return JSONResponse({"error": error}, status_code=400)
        return JSONResponse(tokens)

    async def handle_mcp(request: Request) -> Response:
        server_url = str(request.base_url).rstrip("/")
        www_auth = f'Bearer resource_metadata="{server_url}/.well-known/oauth-protected-resource"'
        auth_header = request.headers.get("authorization", "")
        if not auth_header.startswith("Bearer "):
            return JSONResponse(
                {"error": "Missing bearer token"},
                status_code=401,
                headers={"WWW-Authenticate": www_auth},
            )
        token = auth_header[len("Bearer "):]
        if not oauth.validate_token(token):
            return JSONResponse(
                {"error": "Invalid or expired token"},
                status_code=401,
                headers={"WWW-Authenticate": www_auth},
            )
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
            Route(
                "/.well-known/oauth-authorization-server",
                endpoint=handle_oauth_metadata,
                methods=["GET"],
            ),
            Route(
                "/.well-known/oauth-protected-resource",
                endpoint=handle_protected_resource_metadata,
                methods=["GET"],
            ),
            Route("/register", endpoint=handle_register, methods=["GET", "POST"]),
            Route("/authorize", endpoint=handle_authorize, methods=["GET"]),
            Route("/login", endpoint=handle_login, methods=["GET", "POST"]),
            Route("/token", endpoint=handle_token, methods=["POST"]),
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
        uvicorn.run(
            http_app,
            host=args.host,
            port=args.port,
            proxy_headers=True,
            forwarded_allow_ips="*",
        )
    else:
        asyncio.run(run_stdio())


if __name__ == "__main__":
    main()