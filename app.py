import os
import requests as http_requests
from flask import Flask, render_template, request, jsonify
from engine import AntiPromptInjectionEngine
from google import genai
from google.genai import types

app = Flask(__name__)

# 전역 엔진 인스턴스 (Lazy loading)
engine = None

def get_engine():
    global engine
    if engine is None:
        print("[App] 엔진 초기화 중...")
        engine = AntiPromptInjectionEngine()
        print("[App] 엔진 초기화 완료!")
    return engine

@app.route('/')
def index():
    return render_template('index.html')

# ── URL 크롤링 API ──
@app.route('/api/crawl', methods=['POST'])
def crawl():
    data = request.json
    url = data.get('url', '').strip()

    if not url:
        return jsonify({"success": False, "error": "URL을 입력해 주세요."}), 400

    # http:// 또는 https:// 없으면 자동으로 붙여줌
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url

    try:
        headers = {
            'User-Agent': (
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
                'AppleWebKit/537.36 (KHTML, like Gecko) '
                'Chrome/124.0.0.0 Safari/537.36'
            ),
            'Accept-Language': 'ko-KR,ko;q=0.9,en-US;q=0.8,en;q=0.7',
        }
        resp = http_requests.get(url, headers=headers, timeout=10)
        resp.encoding = resp.apparent_encoding  # 한글 사이트도 정확히 처리

        html = resp.text
        # 너무 길면 앞 50000자만 자름 (토큰 절약)
        if len(html) > 50000:
            html = html[:50000] + '\n<!-- [크롤링 데이터가 너무 길어 일부 잘렸습니다] -->'

        return jsonify({
            "success": True,
            "html": html,
            "url": url,
            "status_code": resp.status_code,
            "size": len(resp.text)
        })

    except http_requests.exceptions.Timeout:
        return jsonify({"success": False, "error": f"⏱️ 응답 시간 초과 (10초). 사이트가 너무 느리거나 접근이 차단되어 있습니다."}), 408
    except http_requests.exceptions.ConnectionError:
        return jsonify({"success": False, "error": f"🔌 연결 실패. URL이 정확한지, 사이트가 온라인인지 확인해 주세요."}), 503
    except Exception as e:
        return jsonify({"success": False, "error": f"❌ 크롤링 중 오류 발생: {str(e)}"}), 500

@app.route('/api/process', methods=['POST'])
def process():
    data = request.json
    html_input = data.get('html_input', '')
    user_query = data.get('user_query', '')
    api_key = data.get('api_key', '')
    history = data.get('history', [])
    
    current_engine = get_engine()
    # 5-Layer 보안 필터 통과 검증
    logs, final_result, blocked = current_engine.process_request(html_input, user_query)
    
    ai_response = ""
    
    # 1. 차단된 경우
    if blocked:
        ai_response = "🚨 보안 위험 탐지: 악성 프롬프트 인젝션 공격이 감지되어 Gemini API 호출이 취소되었습니다."
        logs.append("[LLM Pipeline] 🔴 차단 상태이므로 Gemini API 호출을 수행하지 않고 중단합니다.")
    # 2. 통과된 경우
    else:
        if api_key:
            logs.append("[LLM Pipeline] 🔑 API Key가 제공되었습니다. 신규 Gemini Client를 구성합니다.")
            
            # 실제 API Key에서 확인된 최신 모델 우선순위 목록 (최신순)
            candidate_models = ['gemini-3.5-flash', 'gemini-2.5-flash', 'gemini-2.5-pro', 'gemini-2.0-flash', 'gemini-2.0-flash-lite']
            success = False
            
            try:
                # 신형 SDK의 Client 초기화 및 명시적으로 안정적인 v1 API 버전 강제 세팅
                client = genai.Client(
                    api_key=api_key,
                    http_options=types.HttpOptions(api_version="v1")
                )
                
                # 대화 내역이 있으면 history 기반으로 contents 구성, 없으면 단발성 prompt 구성
                contents = []
                for msg in history:
                    contents.append({
                        "role": msg['role'],
                        "parts": [{"text": msg['text']}]
                    })
                
                # 현재 차례의 메시지 추가
                if history:
                    current_text = user_query
                else:
                    current_text = f"Context (안전성이 검증된 외부 데이터):\n{final_result}\n\nUser Query: {user_query}"
                
                contents.append({
                    "role": "user",
                    "parts": [{"text": current_text}]
                })
                
                # 순차적으로 작동하는 모델을 탐색 (Fallback 메커니즘)
                for model_name in candidate_models:
                    logs.append(f"[LLM Pipeline] ⚡ Gemini API 호출 시도 중 (Model: {model_name})...")
                    try:
                        response = client.models.generate_content(
                            model=model_name,
                            contents=contents
                        )
                        ai_response = response.text
                        logs.append(f"[LLM Pipeline] 🟢 Gemini API({model_name})로부터 성공적으로 응답을 수신했습니다!")
                        
                        # 🟢 출력 가드레일 검사 실행
                        logs.append("[LLM Pipeline] 🔍 AI 답변에 대한 출력 가드레일 검사 중...")
                        if not current_engine.output_compliance_check(ai_response, logs):
                            ai_response = "🚨 보안 위험 탐지: AI 답변에 금지된 요소(스크립트, 무단 링크, API 키 등)가 포함되어 출력이 차단되었습니다."
                            blocked = True
                            logs.append("[LLM Pipeline] 🔴 차단 상태로 변경 — AI 응답이 출력 규정을 위반했습니다.")
                        
                        success = True
                        break
                    except Exception as model_err:
                        logs.append(f"[LLM Pipeline] ⚠️ 모델 '{model_name}' 호출에 실패했습니다. 사유: {str(model_err)}")
                        # 404 Not Found 등이 나면 다음 후보군 모델로 넘어가서 재시도
                        continue
                
                # 만약 모든 후보 모델 시도가 실패했을 경우, 이 키로 접근 가능한 모델 목록을 자동 추적
                if not success:
                    logs.append("[LLM Pipeline] ❌ 제공된 표준 모델들이 모두 실패했습니다. 사용 가능한 모델 목록 조회를 시도합니다...")
                    try:
                        models_list = client.models.list()
                        available_names = [m.name for m in models_list]
                        logs.append(f"[LLM Pipeline] 📋 접근 가능한 모델 목록 추적 성공: {available_names}")
                        
                        clean_names = [name.replace('models/', '') for name in available_names]
                        ai_response = (
                            f"❌ 사용 중이신 API Key에서 표준 모델 권한을 찾지 못했습니다.\n\n"
                            f"🔑 현재 API Key로 접근 가능한 모델 목록:\n"
                            f"{', '.join(clean_names)}\n\n"
                            f"AI Studio에 접속하셔서 API Key의 사용 권한과 결제 한도가 활성화되어 있는지 점검해 주세요."
                        )
                    except Exception as list_err:
                        logs.append(f"[LLM Pipeline] ❌ 사용 가능 모델 목록 조회마저 거부되었습니다: {str(list_err)}")
                        ai_response = (
                            f"❌ API Key 권한 거부 오류가 발생했습니다.\n\n"
                            f"사유: {str(list_err)}\n\n"
                            f"AI Studio에서 API Key가 활성화된 올바른 상태인지 꼭 확인해 주세요!"
                        )
                        
            except Exception as e:
                ai_response = f"❌ Gemini Client 빌드 중 오류가 발생했습니다: {str(e)}"
                logs.append(f"[LLM Pipeline] ❌ Client 오류: {str(e)}")
        else:
            # API Key가 없는 경우 시뮬레이션 모드 작동
            logs.append("[LLM Pipeline] ⚠️ API Key가 입력되지 않았습니다. 시뮬레이션(가상) 모드로 응답을 생성합니다.")
            ai_response = (
                f"🤖 [시뮬레이션 모드 작동 중]\n"
                f"보안 필터를 안전하게 통과했습니다! (Gemini API Key를 입력하시면 실제 AI 답변을 보실 수 있습니다.)\n\n"
                f"🔹 정제된 데이터: \"{final_result[:60]}...\"\n"
                f"🔹 사용자 요청: \"{user_query}\"\n"
                f"🔹 모의 답변: 제시하신 크롤링 데이터 분석을 기반으로 요청하신 '{user_query}' 작업을 완벽하게 수행했습니다."
            )
            logs.append("[LLM Pipeline] 🟢 가상 모의 응답 생성이 완료되었습니다.")
            
    return jsonify({
        "logs": logs,
        "final_result": final_result,
        "blocked": blocked,
        "ai_response": ai_response
    })

if __name__ == '__main__':
    print("UI Server Started! Open http://127.0.0.1:5000 in your browser.")
    # use_reloader=True 로 인해 코드가 수정되면 서버가 자동 재시작됩니다.
    app.run(host='127.0.0.1', port=5000, debug=True, use_reloader=True)
