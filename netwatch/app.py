"""
app.py
Flask application factory and entry point.

Run with:
    sudo python app.py                         # live capture (requires root)
    python app.py --demo                       # demo mode (no root needed)
    python app.py --interface eth0             # specific interface
"""

import sys
import os
import logging
import argparse

# Ensure project root is in path
sys.path.insert(0, os.path.dirname(__file__))

from flask import Flask, render_template
from flask_cors import CORS

from backend.api.api import api
from backend.pipeline import init_pipeline

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
    datefmt='%H:%M:%S'
)
logger = logging.getLogger('netwatch')


def create_app(interface: str = None, warmup_flows: int = 300) -> Flask:
    app = Flask(
        __name__,
        template_folder='frontend/templates',
        static_folder='frontend/static'
    )
    CORS(app, resources={r"/api/*": {"origins": "*"}})

    # Register REST API blueprint
    app.register_blueprint(api)

    # Serve frontend
    @app.route('/')
    def index():
        return render_template('index.html')

    # Start background pipeline
    with app.app_context():
        init_pipeline(interface=interface, warmup_flows=warmup_flows)
        logger.info("NetWatch pipeline initialized.")

    return app


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='NetWatch Anomaly Detection System')
    parser.add_argument('--interface', '-i', default=None,
                        help='Network interface to capture on (e.g., eth0, wlan0)')
    parser.add_argument('--warmup', '-w', type=int, default=100,
                        help='Number of flows to collect before training (default: 100)')
    parser.add_argument('--port', '-p', type=int, default=5000,
                        help='Flask port (default: 5000)')
    parser.add_argument('--demo', action='store_true',
                        help='Run in demo mode without raw packet capture')
    args = parser.parse_args()

    if args.demo:
        logger.info("Starting in DEMO mode — synthetic traffic will be generated.")

    app = create_app(
        interface=args.interface,
        warmup_flows=args.warmup
    )

    logger.info("NetWatch dashboard available at http://localhost:%d", args.port)
    app.run(
        host='0.0.0.0',
        port=args.port,
        debug=False,
        threaded=True,
        use_reloader=False  # prevent double-starting pipeline
    )
