import time
from functools import wraps
from flask import request, jsonify

# Dictionary tracking sliding request timestamps: client_ip -> list of timestamps
_request_records = {}

def limit_requests(limit=60, period=60):
    """
    Decorator implementing basic token-bucket/sliding-window rate limiting.
    
    Parameters:
    - limit (int): Max requests allowed in the timeframe.
    - period (int): Time period window in seconds.
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            client_ip = request.remote_addr
            now = time.time()
            
            if client_ip not in _request_records:
                _request_records[client_ip] = []
                
            # Filter timestamps outside the sliding timeframe window
            _request_records[client_ip] = [t for t in _request_records[client_ip] if t >= now - period]
            
            if len(_request_records[client_ip]) >= limit:
                retry_after = int(period - (now - _request_records[client_ip][0]))
                response = jsonify({
                    'success': False,
                    'message': 'Too many requests. Rate limit exceeded.',
                    'retry_after_seconds': max(1, retry_after)
                })
                response.status_code = 429
                response.headers['Retry-After'] = str(max(1, retry_after))
                return response
                
            # Log this request timestamp
            _request_records[client_ip].append(now)
            return f(*args, **kwargs)
        return decorated_function
    return decorator
