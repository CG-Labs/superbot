#!/bin/sh
# A fake voxl for deploy/test-isolation.sh: botd starts it as a per-user account to view
# that account's screen (docs/adr/0342-per-user-screens-on-one-server.md). It listens on
# --addr and --port like voxl, answers only its token (VOXL_PASSWORD, as ?token=), and
# says which account it runs as and whether it can open its display ($DISPLAY, $XAUTHORITY).
exec python3 -c '
import http.server, os, pwd, subprocess, sys, urllib.parse
args = sys.argv[1:]
addr, port = args[args.index("--addr") + 1], int(args[args.index("--port") + 1])
me = pwd.getpwuid(os.getuid()).pw_name

class View(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        token = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query).get("token", [""])[0]
        if not token or token != os.environ.get("VOXL_PASSWORD"):
            self.send_response(401)
            self.end_headers()
            return
        opened = subprocess.run(["xdpyinfo"], capture_output=True).returncode == 0
        body = ("user=%s;display=%s" % (me, "open" if opened else "denied")).encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass

http.server.HTTPServer((addr, port), View).serve_forever()
' "$@"
