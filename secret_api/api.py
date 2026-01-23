from flask import Flask, jsonify, request
import os

app = Flask(__name__)

# The API token is FLAG{1} from the database (students must obtain via MITM attack)
VALID_API_TOKEN = "FLAG{n3tw0rk_tr4ff1c_1s_n0t_s3cur3}"


def check_auth():
    """Check if the request has valid API token"""
    auth_header = request.headers.get("Authorization")
    token_param = request.args.get("token")

    # Accept token in either Authorization header or query parameter
    if auth_header and auth_header.startswith("Bearer "):
        token = auth_header[7:]
    elif token_param:
        token = token_param
    else:
        return False, "No authentication token provided"

    if token == VALID_API_TOKEN:
        return True, "Valid token"
    else:
        return False, "Invalid token"


@app.route("/")
def index():
    """Root endpoint with API information"""
    return jsonify(
        {
            "service": "Secret API Server",
            "version": "1.0",
            "port": 8888,
            "status": "running",
            "message": "This is a hidden API service. Authentication required.",
            "endpoints": [
                {"path": "/", "method": "GET", "description": "API information"},
                {"path": "/health", "method": "GET", "description": "Health check"},
                {
                    "path": "/flag",
                    "method": "GET",
                    "description": "Get flag (requires authentication)",
                },
                {
                    "path": "/data",
                    "method": "GET",
                    "description": "Get secret data (requires authentication)",
                },
            ],
            "authentication": {
                "type": "Bearer token",
                "header": "Authorization: Bearer <token>",
                "alternative": "?token=<token> query parameter",
                "hint": "The token can be found by intercepting network traffic...",
            },
        }
    )


@app.route("/health")
def health():
    """Health check endpoint (no auth required)"""
    return jsonify({"status": "healthy", "service": "secret_api", "port": 8888})


@app.route("/flag")
def get_flag():
    """
    Get FLAG{3} - requires authentication with FLAG{1}
    Students must:
    1. Discover this service via port scanning (port 8888)
    2. Obtain FLAG{1} via MITM attack on database traffic
    3. Use FLAG{1} as API token to get FLAG{3}
    """
    is_valid, message = check_auth()

    if not is_valid:
        return jsonify(
            {
                "error": "Authentication required",
                "message": message,
                "hint": "You need a valid API token. Try intercepting network traffic...",
            }
        ), 401

    # Return FLAG 3
    return jsonify(
        {
            "success": True,
            "message": "Congratulations! You successfully chained your exploits!",
            "flag": "FLAG{p0rt_kn0ck1ng_4nd_h0n3yp0ts_s4v3_th3_d4y}",
            "steps_completed": [
                "1. Developed a port scanner",
                "2. Discovered this hidden API service on port 8888",
                "3. Performed MITM attack on database traffic",
                "4. Extracted FLAG{1} (the API token) from network packets",
                "5. Used FLAG{1} to authenticate to this API",
                "6. Retrieved FLAG{3}",
            ],
            "next_steps": [
                "Now implement port knocking to protect the SSH service",
                "Deploy a honeypot using the starter template",
            ],
        }
    )


@app.route("/data")
def get_data():
    """Get secret data - requires authentication"""
    is_valid, message = check_auth()

    if not is_valid:
        return jsonify({"error": "Authentication required", "message": message}), 401

    return jsonify(
        {
            "secret_data": [
                {"id": 1, "name": "Project Phoenix", "classification": "Top Secret"},
                {
                    "id": 2,
                    "name": "Operation Nightfall",
                    "classification": "Confidential",
                },
                {"id": 3, "name": "Cipher Key Alpha", "classification": "Restricted"},
            ],
            "message": "This is sensitive data protected by API authentication",
        }
    )


@app.route("/admin")
def admin():
    """Hidden admin endpoint"""
    is_valid, message = check_auth()

    if not is_valid:
        return jsonify({"error": "Authentication required", "message": message}), 401

    return jsonify(
        {
            "admin_panel": True,
            "users": ["admin", "operator", "analyst"],
            "permissions": ["read", "write", "execute"],
            "message": "Admin access granted",
        }
    )


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8888, debug=False)
