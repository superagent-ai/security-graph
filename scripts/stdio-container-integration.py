#!/usr/bin/env python3
"""Exercise the README's Compose stdio launch against a real PostgreSQL container."""
import json
import pathlib
import select
import subprocess
import sys
import tempfile
import uuid


image, network, database_url, container = sys.argv[1:]
root = pathlib.Path(__file__).resolve().parent.parent
with tempfile.TemporaryDirectory(prefix="security-graph-stdio-") as directory:
    project = pathlib.Path(directory)
    env_file = project / ".env"
    env_file.write_text(f"POSTGRES_PASSWORD=integration-only\nDATABASE_URL={database_url}\n")
    override = project / "compose.override.json"
    override.write_text(json.dumps({
        "services": {"server": {"image": image, "pull_policy": "never"}},
        "networks": {"default": {"name": network, "external": True}},
    }))
    command = [
        "docker", "compose", "--project-directory", directory,
        "--env-file", str(env_file), "-f", str(root / "compose.yaml"),
        "-f", str(override), "run", "--rm", "--no-deps", "-T",
        "--name", container, "server", "stdio",
    ]
    process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, text=True)
    request_id = 0

    def request(method, params):
        global request_id
        request_id += 1
        process.stdin.write(json.dumps({"jsonrpc": "2.0", "id": request_id,
                                        "method": method, "params": params}) + "\n")
        process.stdin.flush()
        if not select.select([process.stdout], [], [], 60)[0]:
            raise AssertionError(f"stdio request timed out: {method}")
        line = process.stdout.readline()
        response = json.loads(line)
        assert response.get("id") == request_id and "error" not in response, method
        return response["result"]

    def tool(tool_name, **arguments):
        result = request("tools/call", {"name": tool_name, "arguments": {
            "intent": "Validate the local Compose stdio assessment workflow.",
            "idempotency_key": str(uuid.uuid4()), **arguments,
        }})
        assert not result.get("isError"), tool_name
        return result["structuredContent"]

    try:
        request("initialize", {"protocolVersion": "2025-11-25", "capabilities": {},
                               "clientInfo": {"name": "compose-integration", "version": "test"}})
        process.stdin.write(json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}) + "\n")
        process.stdin.flush()
        tools = request("tools/list", {})["tools"]
        assert len(tools) >= 10
        assert all("intent" in tool["inputSchema"]["required"] for tool in tools)
        asset_id = "compose/" + str(uuid.uuid4())
        tool("create_asset", asset_id=asset_id, name="Compose fixture",
             type="repository", locator="https://github.com/example/stdio-fixture")
        report = tool("create_report", asset_id=asset_id, type="repository",
                      target="example/stdio-fixture@integration")
        finished = tool("finish_report", report_id=report["id"],
                        expected_version=report["version"], status="succeeded")
        assert finished["data"]["status"] == "completed"
        process.stdin.close()
        assert process.wait(timeout=10) == 0, "stdio process did not exit cleanly on EOF"
        assert not process.stdout.read(), "unexpected stdout after the final MCP response"
    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=10)
        process.stdout.close()
        process.stderr.close()

print("Compose stdio discovery, keyless assessment, persistence, and EOF shutdown passed.")
