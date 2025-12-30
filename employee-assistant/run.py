import os
import sys

# Thêm thư mục src vào Python path
src_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'src')
if src_path not in sys.path:
    sys.path.insert(0, src_path)

print(f"✅ Added to Python path: {src_path}")

# Import app từ api module
from api import app

if __name__ == '__main__':
    # Lấy config từ environment
    host = os.getenv('API_HOST', '0.0.0.0')
    port = int(os.getenv('API_PORT', 8080))
    debug = os.getenv('DEBUG', 'True').lower() == 'true'
    
    print(f"🚀 Starting Guardrail API Server...")
    print(f"📍 Host: {host}")
    print(f"🔌 Port: {port}")
    print(f"🐛 Debug: {debug}")
    print(f"🌐 Server running at http://{host}:{port}")
    print(f"💚 Health check: http://{host}:{port}/health")
    
    app.run(host=host, port=port, debug=debug)