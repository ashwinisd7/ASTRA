import logging
from flask import Flask, request, jsonify, redirect, Response, make_response

logger = logging.getLogger(__name__)

def create_mock_app(port: int = 8081) -> Flask:
    """Creates a realistic intentionally vulnerable WordPress mock application."""
    app = Flask("astra_mock_wp")

    MOCK_USERS = [
        {"id": 1, "name": "admin", "slug": "admin", "display_name": "Administrator"},
        {"id": 2, "name": "editor", "slug": "editor", "display_name": "Site Editor"},
        {"id": 3, "name": "testuser", "slug": "testuser", "display_name": "Test User"},
    ]

    USER_PASSWORDS = {
        "admin": "admin123",
        "editor": "editor123",
        "testuser": "password",
    }

    @app.route("/", methods=["GET"])
    def index():
        author_id = request.args.get("author")
        feed = request.args.get("feed")
        rest_route = request.args.get("rest_route")

        # 1. Author archive routing ?author=N
        if author_id is not None:
            try:
                aid = int(author_id)
                match = next((u for u in MOCK_USERS if u["id"] == aid), None)
                if match:
                    return redirect(f"/author/{match['slug']}/", code=301)
                else:
                    return "Author not found", 404
            except ValueError:
                return "Invalid author ID", 400

        # 2. Plain permalink REST API ?rest_route=/wp/v2/users
        if rest_route == "/wp/v2/users":
            return jsonify([
                {
                    "id": u["id"],
                    "name": u["display_name"],
                    "url": f"http://localhost:{port}/author/{u['slug']}/",
                    "description": "",
                    "link": f"http://localhost:{port}/author/{u['slug']}/",
                    "slug": u["slug"],
                }
                for u in MOCK_USERS
            ])

        # 3. RSS feed ?feed=rss2
        if feed in ("rss", "rss2", "atom"):
            return feed_endpoint()

        # Default homepage
        html = """<!DOCTYPE html>
<html>
<head>
    <title>Astra Vulnerable WordPress Testbed</title>
    <meta name="generator" content="WordPress 6.2" />
    <link rel="alternate" type="application/rss+xml" title="Feed" href="/feed/" />
</head>
<body>
    <h1>Welcome to Astra Vulnerable WordPress Instance</h1>
    <p>This server is configured with intentional security weaknesses for take-home assignment evaluation.</p>
</body>
</html>"""
        return Response(html, mimetype="text/html")

    # 4. REST API Endpoints
    @app.route("/wp-json/wp/v2/users", methods=["GET"])
    def rest_users():
        return jsonify([
            {
                "id": u["id"],
                "name": u["display_name"],
                "url": f"http://localhost:{port}/author/{u['slug']}/",
                "description": "",
                "link": f"http://localhost:{port}/author/{u['slug']}/",
                "slug": u["slug"],
            }
            for u in MOCK_USERS
        ])

    @app.route("/wp-json/wp/v2/users/<int:user_id>", methods=["GET"])
    def rest_single_user(user_id):
        match = next((u for u in MOCK_USERS if u["id"] == user_id), None)
        if match:
            return jsonify({
                "id": match["id"],
                "name": match["display_name"],
                "link": f"http://localhost:{port}/author/{match['slug']}/",
                "slug": match["slug"],
            })
        return jsonify({"code": "rest_user_invalid_id", "message": "Invalid user ID.", "data": {"status": 404}}), 404

    @app.route("/wp-json/wp/v2/posts", methods=["GET"])
    def rest_posts():
        return jsonify([
            {
                "id": 1,
                "title": {"rendered": "Hello world!"},
                "_embedded": {
                    "author": [
                        {"id": 1, "name": "admin", "slug": "admin"}
                    ]
                }
            }
        ])

    # 5. Author Archive Page /author/<slug>/
    @app.route("/author/<slug>/", methods=["GET"])
    def author_page(slug):
        match = next((u for u in MOCK_USERS if u["slug"].lower() == slug.lower()), None)
        if not match:
            return "Author Not Found", 404
        html = f"""<!DOCTYPE html>
<html>
<head>
    <title>{match['slug']}, Author at Astra Vulnerable WP</title>
    <link rel="canonical" href="http://localhost:{port}/author/{match['slug']}/" />
</head>
<body class="archive author author-{match['slug']}">
    <h1>Author Archives: {match['display_name']} ({match['slug']})</h1>
</body>
</html>"""
        return Response(html, mimetype="text/html")

    # 6. WordPress Login Endpoint /wp-login.php
    @app.route("/wp-login.php", methods=["GET", "POST"])
    def wp_login():
        action = request.args.get("action")
        if action == "register":
            html = """<!DOCTYPE html>
<html>
<head><title>Registration Form &lsaquo; Astra Vulnerable WP</title></head>
<body class="login">
<div id="login">
    <h1>Registration</h1>
    <form name="registerform" id="registerform" action="/wp-login.php?action=register" method="post">
        <p><label for="user_login">Username<br /><input type="text" name="user_login" id="user_login" class="input" value="" size="20" /></label></p>
        <p id="reg_passmail">Registration confirmation will be emailed to you.</p>
        <p class="submit"><input type="submit" name="wp-submit" id="wp-submit" class="button button-primary button-large" value="Register" /></p>
    </form>
</div>
</body>
</html>"""
            return Response(html, mimetype="text/html")

        if request.method == "POST":
            log = (request.form.get("log") or "").strip().lower()
            pwd = request.form.get("pwd") or ""

            # Check if user exists
            match = next((u for u in MOCK_USERS if u["slug"].lower() == log), None)
            if not match:
                # WordPress Default Error: Unknown user
                err_html = """<div id="login_error"><strong>Error</strong>: Unknown username. Check again or try your email address.</div>"""
                return Response(f"<html><head><title>Log In</title></head><body>{err_html}</body></html>", status=200, mimetype="text/html")

            # User exists! Check password
            correct_pwd = USER_PASSWORDS.get(match["slug"])
            if pwd == correct_pwd:
                # Successful Login! 302 Redirect to wp-admin/
                resp = make_response(redirect("/wp-admin/", code=302))
                resp.set_cookie(f"wordpress_logged_in_astra_hash", f"{match['slug']}|auth_token")
                return resp
            else:
                # WordPress Default Error: Password incorrect for existing user (LEAK!)
                err_html = f"""<div id="login_error"><strong>Error</strong>: The password you entered for the username <strong>{match['slug']}</strong> is incorrect. <a href="/wp-login.php?action=lostpassword">Lost your password?</a></div>"""
                return Response(f"<html><head><title>Log In</title></head><body>{err_html}</body></html>", status=200, mimetype="text/html")

        # GET request returns login form
        html = """<!DOCTYPE html>
<html>
<head><title>Log In &lsaquo; Astra Vulnerable WP</title></head>
<body class="login">
<div id="login">
    <form name="loginform" id="loginform" action="/wp-login.php" method="post">
        <p><label for="user_login">Username or Email Address<br /><input type="text" name="log" id="user_login" class="input" size="20" /></label></p>
        <p><label for="user_pass">Password<br /><input type="password" name="pwd" id="user_pass" class="input" size="20" /></label></p>
        <p class="submit"><input type="submit" name="wp-submit" id="wp-submit" class="button button-primary button-large" value="Log In" /></p>
    </form>
</div>
</body>
</html>"""
        return Response(html, mimetype="text/html")

    # 7. Feed Endpoint /feed/
    @app.route("/feed/", methods=["GET"])
    def feed_endpoint():
        xml = f"""<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0" xmlns:dc="http://purl.org/dc/elements/1.1/">
<channel>
    <title>Astra Vulnerable WP</title>
    <link>http://localhost:{port}</link>
    <item>
        <title>Welcome to the vulnerable testbed</title>
        <dc:creator><![CDATA[admin]]></dc:creator>
        <description>Sample initial post</description>
    </item>
</channel>
</rss>"""
        return Response(xml, mimetype="application/rss+xml")

    # 8. Sitemap Endpoint /wp-sitemap-users-1.xml
    @app.route("/wp-sitemap-users-1.xml", methods=["GET"])
    def sitemap_users():
        xml = f"""<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
    <url><loc>http://localhost:{port}/author/admin/</loc></url>
    <url><loc>http://localhost:{port}/author/editor/</loc></url>
</urlset>"""
        return Response(xml, mimetype="application/xml")

    # 9. oEmbed Endpoint /wp-json/oembed/1.0/embed
    @app.route("/wp-json/oembed/1.0/embed", methods=["GET"])
    def oembed_endpoint():
        return jsonify({
            "version": "1.0",
            "type": "rich",
            "title": "Welcome post",
            "author_name": "admin",
            "author_url": f"http://localhost:{port}/author/admin/",
            "provider_name": "Astra Vulnerable WP"
        })

    # 10. XML-RPC Endpoint /xmlrpc.php
    @app.route("/xmlrpc.php", methods=["GET", "POST"])
    def xmlrpc_endpoint():
        if request.method == "GET":
            return Response("XML-RPC server accepts POST requests only.", status=405, mimetype="text/plain")

        data = request.get_data(as_text=True)
        if "wp.getUsersBlogs" in data:
            if "admin" in data and "admin123" in data:
                xml = f"""<?xml version="1.0" encoding="utf-8"?>
<methodResponse>
  <params>
    <param>
      <value>
        <array><data><value><struct>
          <member><name>isAdmin</name><value><boolean>1</boolean></value></member>
          <member><name>url</name><value><string>http://localhost:{port}/</string></value></member>
        </struct></value></data></array>
      </value>
    </param>
  </params>
</methodResponse>"""
                return Response(xml, mimetype="text/xml")
            else:
                xml = """<?xml version="1.0" encoding="utf-8"?>
<methodResponse>
  <fault><value><struct>
    <member><name>faultCode</name><value><int>403</int></value></member>
    <member><name>faultString</name><value><string>Incorrect username or password.</string></value></member>
  </struct></value></fault>
</methodResponse>"""
                return Response(xml, mimetype="text/xml")

        return Response("XML-RPC server accepts POST requests only.", mimetype="text/plain")

    # 11. Exploit Detection Test Endpoints
    @app.route("/readme.html", methods=["GET"])
    def readme():
        return Response("<br /><h1>Version 6.2</h1><p>WordPress readme file.</p>", mimetype="text/html")

    @app.route("/wp-content/debug.log", methods=["GET"])
    def debug_log():
        return Response("[25-Sep-2026 12:00:00 UTC] PHP Fatal error: Database connection error in /var/www/html/wp-config.php\n", mimetype="text/plain")

    @app.route("/wp-content/uploads/", methods=["GET"])
    def uploads():
        return Response("<!DOCTYPE HTML><html><head><title>Index of /wp-content/uploads/</title></head><body><h1>Index of /wp-content/uploads/</h1></body></html>", mimetype="text/html")

    return app


def run_mock_server(host: str = "127.0.0.1", port: int = 8081):
    """Starts the mock server."""
    app = create_mock_app(port=port)
    import logging
    log = logging.getLogger("werkzeug")
    log.setLevel(logging.ERROR)
    print(f"[*] Starting Astra Vulnerable WordPress Mock Server on http://{host}:{port}")
    app.run(host=host, port=port, debug=False)


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Astra Vulnerable WordPress Mock Server")
    parser.add_argument("--host", default="127.0.0.1", help="Host to bind (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8081, help="Port to bind (default: 8081)")
    args = parser.parse_args()
    run_mock_server(host=args.host, port=args.port)
