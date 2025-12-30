from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from guardrail_service import guardrail_service

app = Flask(__name__, static_folder='../public')
CORS(app)

@app.route('/')
def serve_frontend():
    """Phục vụ frontend"""
    return send_from_directory(app.static_folder, 'index.html')

@app.route('/health', methods=['GET'])
def health_check():
    return jsonify({"status": "healthy", "service": "guardrail-api"})

@app.route('/api/check', methods=['POST'])
def check():
    """Kiểm tra nội dung"""
    data = request.json
    
    if not data or 'text' not in data:
        return jsonify({"error": "Missing 'text' field"}), 400
    
    result = guardrail_service.check_content(data['text'])
    return jsonify(result)

@app.route('/api/chat', methods=['POST'])
def chat():
    """Chat với AI"""
    data = request.json
    
    if not data or 'message' not in data:
        return jsonify({"error": "Missing 'message' field"}), 400
    
    result = guardrail_service.chat_with_ai(data['message'])
    return jsonify(result)

@app.route('/api/batch-check', methods=['POST'])
def batch_check():
    """Kiểm tra nhiều nội dung"""
    data = request.json
    
    if not data or 'texts' not in data:
        return jsonify({"error": "Missing 'texts' array"}), 400
    
    results = []
    for text in data['texts']:
        result = guardrail_service.check_content(text)
        results.append(result)
    
    return jsonify({"count": len(results), "results": results})

if __name__ == '__main__':
    import os
    host = os.getenv('API_HOST', '0.0.0.0')
    port = int(os.getenv('API_PORT', 8080))
    
    print(f"🚀 Server running at http://{host}:{port}")
    app.run(host=host, port=port, debug=True)