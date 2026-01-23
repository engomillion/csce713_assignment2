from flask import Flask, render_template, jsonify
import pymysql
import os
import time

app = Flask(__name__)


def get_db_connection():
    """
    CRITICAL VULNERABILITY: Database connection without TLS/SSL encryption
    All data transmitted between webapp and database is in PLAINTEXT
    This includes queries, results, and sensitive data like flags
    """
    max_retries = 5
    retry_delay = 2

    for attempt in range(max_retries):
        try:
            connection = pymysql.connect(
                host=os.environ.get("DB_HOST", "database"),
                user=os.environ.get("DB_USER", "root"),
                password=os.environ.get("DB_PASS", "insecure_password_2024"),
                database=os.environ.get("DB_NAME", "userdb"),
                # VULNERABILITY: SSL explicitly disabled
                ssl=None,  # No SSL/TLS encryption!
                ssl_disabled=True,
                charset="utf8mb4",
                cursorclass=pymysql.cursors.DictCursor,
            )
            return connection
        except pymysql.err.OperationalError as e:
            if attempt < max_retries - 1:
                print(
                    f"Database connection attempt {attempt + 1} failed, retrying in {retry_delay}s..."
                )
                time.sleep(retry_delay)
            else:
                raise e


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/users")
def users():
    """Fetch and display all users from database"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # Query that will be transmitted in PLAINTEXT over the network
        cursor.execute("SELECT id, username, email, role FROM users ORDER BY id")
        users_list = cursor.fetchall()

        cursor.close()
        conn.close()

        return render_template("users.html", users=users_list)
    except Exception as e:
        return f"Error: {str(e)}", 500


@app.route("/api/users")
def api_users():
    """API endpoint returning users as JSON"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute("SELECT id, username, email, role FROM users ORDER BY id")
        users_list = cursor.fetchall()

        cursor.close()
        conn.close()

        return jsonify(users_list)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/secrets")
def api_secrets():
    """
    API endpoint that queries the secrets table
    CRITICAL: This query contains FLAG{1} and will be transmitted unencrypted!
    Students performing MITM attack will see this in plaintext
    """
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # This query contains sensitive data including the API token (FLAG 1)
        cursor.execute("""
            SELECT id, secret_name, secret_value, description 
            FROM secrets 
            WHERE id = 1
        """)
        secrets_list = cursor.fetchall()

        cursor.close()
        conn.close()

        return jsonify(secrets_list)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/health")
def health():
    """Health check endpoint"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT 1")
        cursor.close()
        conn.close()
        return jsonify({"status": "healthy", "database": "connected"})
    except Exception as e:
        return jsonify({"status": "unhealthy", "error": str(e)}), 500


@app.route("/info")
def info():
    """Information about the application"""
    return render_template("info.html")


if __name__ == "__main__":
    # Wait a bit for database to be fully ready
    time.sleep(5)
    app.run(host="0.0.0.0", port=5000, debug=True)
