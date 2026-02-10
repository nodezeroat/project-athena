#!/usr/bin/env python3
"""
UUID Endpoint Discovery Challenge Server

This Flask application generates a large JavaScript file containing hundreds
of UUID-based API endpoints. One endpoint contains the flag.

The app.min.js file is generated on startup to simulate a real minified
JavaScript application.
"""

from flask import Flask, jsonify
import uuid
import random
import os
import secrets

app = Flask(__name__)

# Configuration
NUM_ENDPOINTS = 1000  # Total number of endpoints to generate

# Generate random flag component on startup

random_component = secrets.token_hex(8)  # 16 character hex string
FLAG = f"FLAG{{UUID_Discovery_Complete_{random_component}}}"

# Store all endpoint UUIDs
endpoint_uuids = []
flag_uuid = None


def generate_minified_js():
    """
    Generate a minified JavaScript file with UUID-based API endpoints.

    This simulates a real-world scenario where a minified frontend
    application leaks API endpoint information.
    """
    global endpoint_uuids, flag_uuid

    print("[*] Generating app.min.js with UUID endpoints...")

    # Generate random UUIDs for endpoints
    endpoint_uuids = [str(uuid.uuid4()) for _ in range(NUM_ENDPOINTS)]

    # Randomly select one endpoint to contain the flag
    flag_uuid = random.choice(endpoint_uuids)

    print(f"[+] Flag will be at: /api/{flag_uuid}")
    print(f"[+] Generating file with {NUM_ENDPOINTS} endpoints...")

    # Create minified JavaScript content
    # This simulates a real minified JS file with API endpoints scattered throughout
    js_content = []

    # Header
    js_content.append('(function(){var API_BASE="/api";')

    # Add endpoints in a minified style
    # We'll create fake function calls and variable assignments with the endpoints
    for i, endpoint_uuid in enumerate(endpoint_uuids):
        # Create various patterns to make it look realistic
        patterns = [
            f'fetch(API_BASE+"/{endpoint_uuid}").then(r=>r.json());',
            f'const url_{i}="/api/{endpoint_uuid}";',
            f'axios.get("/api/{endpoint_uuid}");',
            f'endpoint:"/api/{endpoint_uuid}",',
            f'api.call("/api/{endpoint_uuid}");',
        ]

        # Use random pattern
        js_content.append(random.choice(patterns))

        # Add some random noise every 50 endpoints
        if i % 50 == 0:
            noise = [
                "function(){return fetch(API_BASE);}",
                "var data={};",
                'console.log("API initialized");',
                "const config={timeout:5000};",
            ]
            js_content.append(random.choice(noise))

    # Footer
    js_content.append("})();")

    # Write to file in parent directory (where students will run their script)
    output_path = "/app/app.min.js"  # Inside container
    with open(output_path, "w") as f:
        # Join all lines without newlines to simulate minification
        # But add some line breaks to make it more realistic
        content = "".join(js_content)

        # Add line breaks every ~500 characters for readability
        lines = []
        while content:
            chunk_size = random.randint(400, 600)
            lines.append(content[:chunk_size])
            content = content[chunk_size:]

        f.write("\n".join(lines))

    print(f"[+] Generated app.min.js ({os.path.getsize(output_path)} bytes)")
    print(f"[+] File location: {output_path}")


# Generate the file on startup
generate_minified_js()


@app.route("/api/health", methods=["GET"])
def health_check():
    """Health check endpoint."""
    return jsonify({"status": "healthy", "endpoints": len(endpoint_uuids)}), 200


@app.route("/api/<endpoint_uuid>", methods=["GET"])
def api_endpoint(endpoint_uuid):
    """
    Generic endpoint handler for all UUID-based endpoints.

    Args:
        endpoint_uuid: The UUID from the URL path

    Returns:
        JSON response with either the flag or dummy data
    """
    # Check if this is a valid endpoint
    if endpoint_uuid not in endpoint_uuids:
        return (
            jsonify(
                {
                    "error": "Endpoint not found",
                    "message": "This UUID is not registered",
                }
            ),
            404,
        )

    # Check if this is the flag endpoint
    if endpoint_uuid == flag_uuid:
        return (
            jsonify(
                {
                    "status": "success",
                    "message": "Congratulations! You found the hidden endpoint!",
                    "flag": FLAG,
                }
            ),
            200,
        )

    # Return dummy data for all other endpoints
    dummy_responses = [
        {
            "status": "ok",
            "data": {"id": endpoint_uuid, "value": random.randint(1, 1000)},
        },
        {"status": "success", "result": "Operation completed"},
        {"message": "Data retrieved", "count": random.randint(1, 100)},
        {"info": "Endpoint active", "timestamp": "2024-01-01T00:00:00Z"},
        {"response": "Valid request", "code": 200},
    ]

    return jsonify(random.choice(dummy_responses)), 200


if __name__ == "__main__":
    print("=" * 60)
    print("UUID Endpoint Discovery Challenge Server")
    print("=" * 60)
    print("[*] Running on http://0.0.0.0:5000")
    print("[*] Health check: http://localhost:5001/api/health")
    print(f"[*] Total endpoints: {NUM_ENDPOINTS}")
    print(f"[*] Flag UUID: {flag_uuid}")
    print(f"[*] Flag: {FLAG}")
    print("=" * 60)
    print("\nStudents should:")
    print("1. Parse app.min.js to extract UUID endpoints")
    print("2. Test each endpoint with HTTP GET requests")
    print("3. Find the endpoint that returns the flag\n")

    app.run(host="0.0.0.0", port=5000, debug=False)
