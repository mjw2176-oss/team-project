from flask import Flask, render_template, request, jsonify
from engine import AntiPromptInjectionEngine

app = Flask(__name__)

# 전역 엔진 인스턴스 (Lazy loading)
engine = None

def get_engine():
    global engine
    if engine is None:
        print("[App] 엔진 초기화 및 LLM-Guard 모델 로딩 중...")
        engine = AntiPromptInjectionEngine()
        print("[App] 엔진 초기화 완료!")
    return engine

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/process', methods=['POST'])
def process():
    data = request.json
    html_input = data.get('html_input', '')
    user_query = data.get('user_query', '')
    
    current_engine = get_engine()
    logs, final_result, blocked = current_engine.process_request(html_input, user_query)
    
    return jsonify({
        "logs": logs,
        "final_result": final_result,
        "blocked": blocked
    })

if __name__ == '__main__':
    print("UI Server Started! Open http://127.0.0.1:5000 in your browser.")
    # use_reloader=True 로 인해 코드가 수정되면 서버가 자동 재시작됩니다.
    app.run(host='127.0.0.1', port=5000, debug=True, use_reloader=True)
