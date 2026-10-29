import sys
import os

# Ensure the root project directory is discoverable by the lambda runtime
current_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.abspath(os.path.join(current_dir, '..', '..'))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

# Inform config that we are running inside Netlify Functions
os.environ['NETLIFY'] = 'true'

import serverless_wsgi
from app import app

def handler(event, context):
    """
    AWS Lambda / Netlify Functions serverless handler for Flask.
    Converts incoming API Gateway / Netlify HTTP events to WSGI calls and back.
    """
    return serverless_wsgi.handle_request(app, event, context)
