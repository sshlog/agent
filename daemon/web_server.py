import logging
import threading
import json
import os
from functools import wraps
from flask import Flask, render_template_string, jsonify, request, Response
import simple_websocket
# Explicitly import the threading driver to ensure PyInstaller bundles it
try:
    import engineio.async_drivers.threading
except ImportError:
    pass

from flask_socketio import SocketIO, emit, join_room, leave_room
from comms.mq_client import MQClient
from comms.dtos import ShellSendKeysRequestDto
from comms.event_types import SSHTRACE_EVENT_TERMINAL_UPDATE, SSHTRACE_EVENT_CLOSE_CONNECTION

logger = logging.getLogger('sshlog_web')

HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>SSHLog Dashboard</title>
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/xterm@5.3.0/css/xterm.css" />
    <script src="https://cdn.jsdelivr.net/npm/xterm@5.3.0/lib/xterm.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/xterm-addon-fit@0.8.0/lib/xterm-addon-fit.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/socket.io/4.0.1/socket.io.js"></script>
    <style>
        body { font-family: sans-serif; margin: 20px; background: #f4f4f4; display: flex; flex-direction: column; height: 95vh; }
        h1 { color: #333; }
        #sessions-container { background: #fff; padding: 20px; border-radius: 5px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); margin-bottom: 20px; }
        table { width: 100%; border-collapse: collapse; margin-top: 10px; }
        th, td { text-align: left; padding: 10px; border-bottom: 1px solid #ddd; }
        th { background-color: #eee; }
        button { padding: 5px 10px; cursor: pointer; background: #007bff; color: #fff; border: none; border-radius: 3px; }
        button:hover { background: #0056b3; }
        #terminal-wrapper { flex-grow: 1; display: none; flex-direction: column; }
        #terminal-container { flex-grow: 1; background: #000; padding: 10px; border-radius: 5px; overflow: hidden; }
        .close-btn { background: #dc3545; }
        .close-btn:hover { background: #a71d2a; }
        .watching-row { background-color: #e2e6ea; }
    </style>
</head>
<body>
    <h1>SSHLog Active Sessions</h1>
    
    <div id="sessions-container">
        <div id="session-list">Loading sessions...</div>
    </div>
    
    <div id="terminal-wrapper">
        <div style="margin-bottom: 10px; display: flex; align-items: center;">
            <button class="close-btn" onclick="closeTerminal()">Close Terminal</button>
            <label style="margin-left: 15px;"><input type="checkbox" id="readonly-mode" checked> Read-Only Mode</label>
        </div>
        <div id="terminal-container"></div>
    </div>

    <script>
        var socket = io();
        var term;
        var fitAddon;
        var currentPtmPid = -1;

        socket.on('connect', function() {
            console.log('Connected to SSHLog Daemon');
            refreshSessions();
        });

        function formatDuration(ms) {
            if (!ms) return '-';
            let seconds = Math.floor((Date.now() - ms) / 1000);
            if (seconds < 0) seconds = 0;
            const h = Math.floor(seconds / 3600);
            const m = Math.floor((seconds % 3600) / 60);
            const s = seconds % 60;
            if (h > 0) return `${h}h ${m}m`;
            if (m > 0) return `${m}m ${s}s`;
            return `${s}s`;
        }

        function refreshSessions() {
            fetch('/api/sessions')
                .then(response => response.json())
                .then(data => {
                    if (data.length === 0) {
                        document.getElementById('session-list').innerHTML = '<p>No active SSH sessions.</p>';
                        return;
                    }
                    var html = '<table><tr><th>User</th><th>PID</th><th>TTY</th><th>Client IP</th><th>Age</th><th>Action</th></tr>';
                    data.forEach(s => {
                        const isWatching = (s.ptm_pid == currentPtmPid);
                        const rowClass = isWatching ? 'class="watching-row"' : '';
                        html += `<tr ${rowClass}>
                            <td>${s.user}</td>
                            <td>${s.ptm_pid}</td>
                            <td>${s.tty_id}</td>
                            <td>${s.client_ip}</td>
                            <td>${formatDuration(s.start_time)}</td>
                            <td><button onclick="watchSession(${s.ptm_pid})" ${isWatching ? 'disabled' : ''}>${isWatching ? 'Watching...' : 'Join / Watch'}</button></td>
                        </tr>`;
                    });
                    html += '</table>';
                    document.getElementById('session-list').innerHTML = html;
                });
        }

        setInterval(refreshSessions, 5000);

        function watchSession(ptmPid) {
            currentPtmPid = ptmPid;
            refreshSessions();
            document.getElementById('terminal-wrapper').style.display = 'flex';
            
            if (term) term.dispose();
            term = new Terminal({
                cursorBlink: true,
                fontFamily: 'Menlo, Monaco, "Courier New", monospace',
                fontSize: 14
            });
            fitAddon = new FitAddon.FitAddon();
            term.loadAddon(fitAddon);
            
            term.open(document.getElementById('terminal-container'));
            fitAddon.fit();
            
            term.onData(function(data) {
                if (!document.getElementById('readonly-mode').checked) {
                    socket.emit('term_input', {ptm_pid: currentPtmPid, data: data});
                }
            });

            socket.emit('join_session', {ptm_pid: currentPtmPid});

            // Force a redraw to get initial state
            socket.emit('term_input', {ptm_pid: currentPtmPid, force_redraw: true, data: ''});
            
            window.addEventListener('resize', fitTerminal);
        }
        
        function fitTerminal() {
            if (fitAddon) fitAddon.fit();
        }

        function closeTerminal() {
            document.getElementById('terminal-wrapper').style.display = 'none';
            if (currentPtmPid != -1) {
                socket.emit('leave_session', {ptm_pid: currentPtmPid});
            }
            if (term) term.dispose();
            currentPtmPid = -1;
            window.removeEventListener('resize', fitTerminal);
            refreshSessions();
        }

        socket.on('term_output', function(msg) {
            if (msg.ptm_pid == currentPtmPid && term) {
                term.write(msg.data);
            }
        });
    </script>
</body>
</html>
"""

def check_auth(username, password):
    """Check if a username / password combination is valid."""
    env_user = os.environ.get('SSHLOG_WEB_USER', 'admin')
    env_pass = os.environ.get('SSHLOG_WEB_PASS', 'admin')
    return username == env_user and password == env_pass

def authenticate():
    """Sends a 401 response that enables basic auth"""
    return Response(
    'Could not verify your access level for that URL.\n'
    'You have to login with proper credentials', 401,
    {'WWW-Authenticate': 'Basic realm="Login Required"'})

def requires_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.authorization
        if not auth or not check_auth(auth.username, auth.password):
            return authenticate()
        return f(*args, **kwargs)
    return decorated

class SSHLogWebServer:
    def __init__(self, session_tracker, host='127.0.0.1', port=5000):
        self.session_tracker = session_tracker
        self.host = host
        self.port = port
        self.app = Flask(__name__)
        self.socketio = SocketIO(self.app, cors_allowed_origins="*", async_mode='threading')
        self.mq_client = MQClient()
        
        self.app.add_url_rule('/', 'index', requires_auth(self.index))
        self.app.add_url_rule('/api/sessions', 'get_sessions', requires_auth(self.get_sessions))
        self.socketio.on_event('term_input', self.on_term_input)
        self.socketio.on_event('join_session', self.on_join_session)
        self.socketio.on_event('leave_session', self.on_leave_session)
        self.buffers = {}

    def start(self):
        t = threading.Thread(target=self._run)
        t.daemon = True
        t.start()
        logger.info(f"Web server started on port {self.port}")

    def _run(self):
        self.socketio.run(self.app, host=self.host, port=self.port, use_reloader=False, log_output=False)

    def index(self):
        return render_template_string(HTML_TEMPLATE)

    def get_sessions(self):
        sessions = []
        try:
            # Iterate over the tracker's sessions
            for s in self.session_tracker.get_sessions():
                sessions.append({
                    'user': s['username'],
                    'ptm_pid': s['ptm_pid'],
                    'tty_id': s['tty_id'],
                    'client_ip': s['tcp_info']['client_ip'],
                    'start_time': s.get('start_time')
                })
        except Exception as e:
            logger.error(f"Error listing sessions: {e}")
        return jsonify(sessions)

    def on_join_session(self, data):
        ptm_pid = data.get('ptm_pid')
        if ptm_pid:
            join_room(str(ptm_pid))

    def on_leave_session(self, data):
        ptm_pid = data.get('ptm_pid')
        if ptm_pid:
            leave_room(str(ptm_pid))

    def on_term_input(self, data):
        ptm_pid = data.get('ptm_pid')
        keys = data.get('data')
        force_redraw = data.get('force_redraw', False)
        
        if ptm_pid:
            if force_redraw and ptm_pid in self.buffers:
                emit('term_output', {
                    'ptm_pid': ptm_pid,
                    'data': self.buffers[ptm_pid]
                })

            # Use the internal MQ client to send keystrokes to the daemon's MQ server
            dto = ShellSendKeysRequestDto(ptm_pid=ptm_pid, keys=keys, force_redraw=force_redraw)
            self.mq_client.make_request(dto)

    def process_event(self, event_data):
        event_type = event_data.get('event_type')
        ptm_pid = event_data.get('ptm_pid')

        # Broadcast terminal updates to all connected web clients
        if event_type == SSHTRACE_EVENT_TERMINAL_UPDATE:
            data = event_data.get('terminal_data')
            if data:
                if ptm_pid not in self.buffers:
                    self.buffers[ptm_pid] = ""
                self.buffers[ptm_pid] += data
                if len(self.buffers[ptm_pid]) > 16384:
                    self.buffers[ptm_pid] = self.buffers[ptm_pid][-16384:]

            self.socketio.emit('term_output', {
                'ptm_pid': ptm_pid,
                'data': data
            }, room=str(ptm_pid))
        elif event_type == SSHTRACE_EVENT_CLOSE_CONNECTION:
            if ptm_pid in self.buffers:
                del self.buffers[ptm_pid]