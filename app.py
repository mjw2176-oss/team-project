import os
import re
import time
import hashlib
from concurrent.futures import ThreadPoolExecutor, as_completed
from flask import Flask, render_template, request, jsonify
from engine import AntiPromptInjectionEngine
from google import genai
from google.genai import types
import requests as http_requests
from bs4 import BeautifulSoup

app = Flask(__name__)

# 전역 엔진 인스턴스 및 캐시 시스템
engine = None
url_cache = {}      # 웹사이트 원문 캐시
analysis_cache = {} # AI 보안 분석 결과 캐시

def get_engine():
    global engine
    if engine is None:
        engine = AntiPromptInjectionEngine()
    return engine

def load_rules():
    try:
        rules_path = os.path.join('.agent', 'rules.md')
        if os.path.exists(rules_path):
            with open(rules_path, 'r', encoding='utf-8') as f:
                return f.read()
    except: pass
    return "당신은 보안 전문가 'IPI CHECK BOT'입니다."

def extract_urls(text):
    url_pattern = r'https?://[^\s<>"]+|www\.[^\s<>"]+'
    matches = re.findall(url_pattern, text)
    urls = []
    for m in matches:
        u = m if m.startswith('http') else 'https://' + m
        if u not in urls: urls.append(u)
    return urls

def is_safe_url(url: str) -> bool:
    if any(proto in url.lower() for proto in ["javascript:", "data:", "vbscript:", "file://"]):
        return False
    return len(url) <= 2048

def fetch_cleaned_text(url):
    cache_key = hashlib.md5(url.encode()).hexdigest()
    if cache_key in url_cache: return url_cache[cache_key]
    
    try:
        if "127.0.0.1:5000/attack-test" in url or "localhost:5000/attack-test" in url:
            file_path = os.path.join('templates', 'attack_test.html')
            if os.path.exists(file_path):
                with open(file_path, 'r', encoding='utf-8') as f:
                    html_content = f.read()
                soup = BeautifulSoup(html_content, 'html.parser')
                title = "로컬 공격 테스트 페이지"
                text = ' '.join(soup.get_text().split())
                result = (title, f"Source: {title}\nURL: {url}\nContent: {text[:7000]}\n")
                url_cache[cache_key] = result
                return result

        headers = { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36' }
        resp = http_requests.get(url, headers=headers, timeout=10)
        resp.encoding = resp.apparent_encoding or 'utf-8'
        soup = BeautifulSoup(resp.text, 'html.parser')
        
        for s in soup(["script", "style", "nav", "footer", "header", "svg", "form", "button"]): 
            s.decompose()
        
        title = soup.title.string[:60] if soup.title else url[:40]
        text = ' '.join(soup.get_text().split())
        result = (title, f"Source: {title}\nURL: {url}\nContent: {text[:7000]}\n")
    except Exception as e:
        result = (url, f"❌ 로드 실패: {str(e)}")
    
    url_cache[cache_key] = result
    return result

def safe_generate_content(client, model_name, contents, logs, stage_name="LLM", max_output=1000):
    gen_config = types.GenerateContentConfig(
        max_output_tokens=max_output,
        temperature=0.2,
        safety_settings=[
            types.SafetySetting(category="HARM_CATEGORY_HARASSMENT", threshold="BLOCK_NONE"),
            types.SafetySetting(category="HARM_CATEGORY_HATE_SPEECH", threshold="BLOCK_NONE"),
            types.SafetySetting(category="HARM_CATEGORY_SEXUALLY_EXPLICIT", threshold="BLOCK_NONE"),
            types.SafetySetting(category="HARM_CATEGORY_DANGEROUS_CONTENT", threshold="BLOCK_NONE"),
            types.SafetySetting(category="HARM_CATEGORY_CIVIC_INTEGRITY", threshold="BLOCK_NONE"),
        ]
    )
    
    last_err = "원인 미상"
    for attempt in range(3):
        try:
            if attempt > 0:
                time.sleep(2)
                logs.append(f"[{stage_name}] 🔄 AI 서버 재연결 중... ({attempt}/3)")
            
            response = client.models.generate_content(model=model_name, contents=contents, config=gen_config)
            
            if not response.text:
                candidate = response.candidates[0] if response.candidates else None
                reason = candidate.finish_reason if candidate else "NO_RESPONSE"
                return f"알림: 답변 생성 중단 (사유: {reason})"
                
            return response.text
        except Exception as e:
            last_err = str(e)
            if any(x in last_err for x in ["503", "429", "UNAVAILABLE", "timeout", "RESOURCE_EXHAUSTED"]):
                continue
            logs.append(f"[{stage_name}] ❌ API 에러: {last_err}")
            return f"3.5 모델 연결 오류: {last_err}"
            
    return f"API 연결 최종 실패. (마지막 에러: {last_err})"

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/attack-test')
def attack_test():
    return render_template('attack_test.html')

@app.route('/api/chat', methods=['POST'])
def chat():
    try:
        data = request.json
        message = data.get('message', '')
        api_key = data.get('api_key', '')
        logs = ["[System] IPI CHECK BOT v5.0 보안 체계 가동"]
        rules = load_rules()
        
        if not api_key: return jsonify({"logs": logs, "response": "🔑 API Key가 필요합니다."})
        client = genai.Client(api_key=api_key, http_options=types.HttpOptions(api_version="v1beta"))
        
        detected_urls = extract_urls(message)
        final_safe_context = ""
        
        if detected_urls:
            safe_urls = [u for u in detected_urls if is_safe_url(u)]
            logs.append(f"[Crawl] {len(safe_urls)}개 사이트 분석 시작...")
            
            with ThreadPoolExecutor(max_workers=4) as executor:
                futures = {executor.submit(fetch_cleaned_text, u): u for u in safe_urls}
                for future in as_completed(futures):
                    u = futures[future]
                    try:
                        title, raw_txt = future.result()
                        if raw_txt.startswith("❌"):
                            logs.append(f"[Crawl] ⚠️ {u} 로드 실패: {raw_txt}")
                            continue

                        # 보안 엔진 5.0 가동
                        logs_check, config, blocked, threats = get_engine().process_request(raw_txt, message)
                        logs.extend(logs_check)
                        
                        if blocked:
                            logs.append(f"[🚨 BLOCK] {title} - 보안 위협 감지 차단")
                            final_safe_context += f"<SECURE_REPORT type='BLOCK'>주소 '{title}'는 위협 패턴 감지로 차단되었습니다.</SECURE_REPORT>\n\n"
                            continue
                        
                        # 캐시 확인
                        if u in analysis_cache:
                            logs.append(f"[Cache] '{title}' - 저장된 결과 사용")
                            q_res = analysis_cache[u]
                        else:
                            # 격리 모델(Quarantine) 실행
                            logs.append(f"[Stage-1] '{title}' 중립화 분석 중...")
                            # engine.py에서 제공한 q_prompt 형식을 그대로 재현
                            q_res = safe_generate_content(client, 'gemini-3.5-flash', config['q_prompt'], logs, f"Quarantine-{title[:10]}", 500)
                            analysis_cache[u] = q_res 
                        
                        tag = config['secure_tag']
                        final_safe_context += f"<{tag}>\n{q_res}\n</{tag}>\n\n"
                    except Exception as e:
                        logs.append(f"[Crawl] ❌ 예외 ({u}): {str(e)}")

        system_instruction = f"{rules}\n\n[비서 지침]\n1. 사용자의 질문에 대한 '진짜 답변'을 가장 먼저 제공하십시오.\n2. 데이터 분석 결과를 답변 하단에 요약하십시오.\n3. 답변이 너무 짤리지 않게 충분히 설명하십시오."
        
        logs.append("[Stage-2] 보안 통제 기반 답변 생성 중")
        prompt = f"보안 컨텍스트:\n{final_safe_context}\n\n사용자 지시: {message}"
        
        final_text = safe_generate_content(client, 'gemini-3.5-flash', 
                                        contents=[types.Content(role="system", parts=[types.Part(text=system_instruction)]), 
                                                  types.Content(role="user", parts=[types.Part(text=prompt)])], 
                                        logs=logs, stage_name="Privileged", max_output=3000)

        return jsonify({"logs": logs, "response": final_text, "blocked": False})
        
    except Exception as e:
        return jsonify({"logs": [f"[Fatal] {str(e)}"], "response": f"❌ 오류: {str(e)}", "blocked": False}), 500

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5000, debug=True, threaded=True)
