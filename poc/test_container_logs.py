"""
POC: Test container logs via Unraid GraphQL API.

Tests whether the docker.logs query is supported by the Unraid 7.2.2 schema.
Tries multiple approaches:
  1. Library's get_container_logs() method
  2. Raw GraphQL query for docker.logs
  3. Introspection of the Docker type to see if 'logs' field exists

Usage:
    UNRAID_HOST=tower.local UNRAID_API_KEY=your-key python test_container_logs.py
"""

import argparse
import asyncio
import json
import os
import sys


# The exact query the library uses
LOGS_QUERY = """
query GetContainerLogs($id: PrefixedID!, $tail: Int) {
    docker {
        logs(id: $id, tail: $tail) {
            containerId
            lines {
                timestamp
                message
            }
            cursor
        }
    }
}
"""

# Introspect the Docker type to see available fields
DOCKER_INTROSPECTION = """
query {
    __type(name: "DockerQuery") {
        name
        fields {
            name
            type { name kind }
            args { name type { name } }
        }
    }
}
"""

# Fallback: introspect via different type names
DOCKER_TYPE_NAMES = ["DockerQuery", "Docker", "DockerMutation", "Query"]


async def main(host: str, api_key: str, verify_ssl: bool = False):
    try:
        from unraid_api import UnraidClient
        from unraid_api.exceptions import UnraidAPIError
    except ImportError:
        print("ERROR: unraid-api package not installed.")
        print("Run: pip install unraid-api")
        sys.exit(1)

    print("=" * 60)
    print("CONTAINER LOGS - POC TEST")
    print("=" * 60)
    print(f"Target: {host}\n")

    try:
        async with UnraidClient(host, api_key, verify_ssl=verify_ssl) as client:
            connected = await client.test_connection()
            if not connected:
                print("FAIL: Could not connect.")
                return

            print("OK: Connected\n")

            # ── Step 1: Get a running container ID ──────────────
            print("-" * 60)
            print("Step 1: Finding a running container...")
            print("-" * 60)

            containers = await client.typed_get_containers()
            running = [c for c in containers if c.state == "RUNNING"]

            if not running:
                print("No running containers found. Cannot test logs.")
                return

            target = running[0]
            print(f"Using: {target.name} (id: {target.id})\n")

            # ── Step 2: Try library method ──────────────────────
            print("-" * 60)
            print("Step 2: Testing client.get_container_logs()")
            print("-" * 60)

            try:
                result = await client.get_container_logs(target.id, tail=5)
                print(f"Return type: {type(result).__name__}")
                print(f"Return value: {json.dumps(result, indent=2, default=str)}")

                lines = result.get("lines", [])
                print(f"\nLines count: {len(lines)}")
                if lines:
                    print("First line:")
                    print(f"  type: {type(lines[0]).__name__}")
                    print(f"  value: {json.dumps(lines[0], default=str)}")
                    if isinstance(lines[0], dict):
                        print(f"  keys: {list(lines[0].keys())}")
                        print(f"  timestamp: {lines[0].get('timestamp')}")
                        print(f"  message: {lines[0].get('message')}")
                print()
            except UnraidAPIError as e:
                print(f"UnraidAPIError: {e}")
                if hasattr(e, 'errors'):
                    print(f"GraphQL errors: {json.dumps(e.errors, indent=2, default=str)}")
                print()
            except Exception as e:
                print(f"{type(e).__name__}: {e}")
                print()

            # ── Step 3: Try raw GraphQL query ───────────────────
            print("-" * 60)
            print("Step 3: Testing raw GraphQL query")
            print("-" * 60)

            try:
                raw = await client.query(LOGS_QUERY, {"id": target.id, "tail": 5})
                print(f"Raw response: {json.dumps(raw, indent=2, default=str)}")
                print()
            except UnraidAPIError as e:
                print(f"UnraidAPIError: {e}")
                if hasattr(e, 'errors'):
                    print(f"GraphQL errors: {json.dumps(e.errors, indent=2, default=str)}")
                print()
            except Exception as e:
                print(f"{type(e).__name__}: {e}")
                print()

            # ── Step 4: Introspect Docker type ──────────────────
            print("-" * 60)
            print("Step 4: Schema introspection — looking for 'logs' field")
            print("-" * 60)

            for type_name in DOCKER_TYPE_NAMES:
                query = f'''
                query {{
                    __type(name: "{type_name}") {{
                        name
                        fields {{
                            name
                            type {{ name kind }}
                            args {{ name type {{ name }} }}
                        }}
                    }}
                }}
                '''
                try:
                    result = await client.query(query)
                    type_data = result.get("__type")
                    if type_data and type_data.get("fields"):
                        print(f"\n  Type '{type_name}' fields:")
                        for f in type_data["fields"]:
                            marker = " <-- LOGS!" if f["name"] == "logs" else ""
                            args_str = ""
                            if f.get("args"):
                                args_str = f" (args: {', '.join(a['name'] for a in f['args'])})"
                            print(f"    - {f['name']}: {f['type'].get('name', f['type'].get('kind', '?'))}{args_str}{marker}")
                    else:
                        print(f"  Type '{type_name}': not found or no fields")
                except Exception as e:
                    print(f"  Type '{type_name}': error — {e}")

            print()
            print("=" * 60)
            print("DONE")
            print("=" * 60)

    except Exception as e:
        print(f"FAIL: {type(e).__name__}: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Test container logs query")
    parser.add_argument("--host", default=os.environ.get("UNRAID_HOST", ""),
                        help="Unraid server hostname or IP")
    parser.add_argument("--api-key", default=os.environ.get("UNRAID_API_KEY", ""),
                        help="Unraid API key")
    parser.add_argument("--no-verify-ssl", action="store_true", default=True,
                        help="Disable SSL verification (default)")

    args = parser.parse_args()

    if not args.host or not args.api_key:
        print("ERROR: Both --host and --api-key are required.")
        print("Set via arguments or UNRAID_HOST / UNRAID_API_KEY env vars.")
        sys.exit(1)

    asyncio.run(main(args.host, args.api_key))
