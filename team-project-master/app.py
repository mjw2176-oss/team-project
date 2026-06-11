import os
import re
import time
import hashlib
import json
import requests as http_requests
from bs4 import BeautifulSoup
from flask import Flask, render_template, request, jsonify
from engine import AntiPromptInjectionEngine
from google import genai
from google.genai import types
from concurrent.futures import ThreadPoolExecutor, as_completed

app = Flask(__name__)

# 전역 엔진 인스턴스
engine = None
url_cache = {}
TEST_MODE = False

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
        # 로설 서버(localhost/127.0.0.1)의 경우 네트워크를 거치지 않고 직접 파일 읽기 (데드락/방화벽 우회)
        if "127.0.0.1:5000/attack-test" in url or "localhost:5000/attack-test" in url:
            file_path = os.path.join('templates', 'attack_test.html')
            if os.path.exists(file_path):
                with open(file_path, 'r', encoding='utf-8') as f:
                    html_content = f.read()
                soup = BeautifulSoup(html_content, 'html.parser')
                title = "로컬 공격 테스트 페이지 (Direct Load)"
                text = ' '.join(soup.get_text().split())
                result = (title, f"Source: {title}\nURL: {url}\nContent: {text[:7000]}\n")
                url_cache[cache_key] = result
                return result

        headers = { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36' }
        resp = http_requests.get(url, headers=headers, timeout=10)
        resp.encoding = resp.apparent_encoding or 'utf-8'
        soup = BeautifulSoup(resp.text, 'html.parser')
        
        # 7,000자 이내로 핵심만 추출 (속도 최적화)
        for s in soup(["script", "style", "nav", "footer", "header", "svg", "form", "button"]): 
            s.decompose()
        
        title = soup.title.string[:60] if soup.title else url[:40]
        text = ' '.join(soup.get_text().split())
        result = (title, f"Source: {title}\nURL: {url}\nContent: {text[:7000]}\n")
    except Exception as e:
        result = (url, f"❌ 로딩 실패: {str(e)}")
    
    url_cache[cache_key] = result
    return result

def safe_generate_content(client, model_name, contents, logs, stage_name="LLM", max_output=1000):
    global TEST_MODE
    if TEST_MODE:
        return '{"summary": "테스트 요약", "content": "테스트 본문", "security_note": ""}' if "Quarantine" in stage_name else "테스트 답변입니다."
    
    # 보안 분석 시 내부 필터 오작동을 최소화하기 위한 설정
    gen_config = types.GenerateContentConfig(
        max_output_tokens=max_output,
        temperature=0.4,
        safety_settings=[
            types.SafetySetting(category="HARM_CATEGORY_HARASSMENT", threshold="BLOCK_NONE"),
            types.SafetySetting(category="HARM_CATEGORY_HATE_SPEECH", threshold="BLOCK_NONE"),
            types.SafetySetting(category="HARM_CATEGORY_SEXUALLY_EXPLICIT", threshold="BLOCK_NONE"),
            types.SafetySetting(category="HARM_CATEGORY_DANGEROUS_CONTENT", threshold="BLOCK_NONE"),
        ]
    )
    
    for attempt in range(2):
        try:
            if attempt > 0:
                time.sleep(1.5)
                logs.append(f"[{stage_name}] 🔄 재연결 시도 중... ({attempt}/2)")
            
            response = client.models.generate_content(model=model_name, contents=contents, config=gen_config)
            
            if not response.text:
                finish_reason = response.candidates[0].finish_reason if response.candidates else "Unknown"
                logs.append(f"[{stage_name}] ⚠️ 답변 중단 (사유: {finish_reason})")
                return f"보안 분석 중 답변이 중단되었습니다. (사유: {finish_reason})"
                
            return response.text
        except Exception as e:
            err_str = str(e).lower()
            # 429 Quota Exceeded / Rate Limit는 즉시 반환하여 프론트엔드 대기 시간 방지
            if "429" in err_str or "resource_exhausted" in err_str or "quota" in err_str:
                logs.append(f"[{stage_name}] ❌ API 호출 한도 초과: {str(e)}")
                return "🔑 API 호출 한도(Quota)를 초과했거나 요청이 너무 많습니다. 잠시 후(1분 뒤) 다시 시도해 주세요."
            
            # 503 / UNAVAILABLE 등 일시적 에러는 재시도 진행
            if any(x in err_str for x in ["503", "unavailable"]):
                logs.append(f"[{stage_name}] ⚠️ 일시적 서버 에러 감지 (재시도 예정): {str(e)}")
                continue
                
            logs.append(f"[{stage_name}] ❌ 시스템 에러: {str(e)}")
            return f"오류 발생: {str(e)}"
    return "서버 상태가 불안정하여 답변을 완성하지 못했습니다."

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

                        logs.append(f"[Stage-1] {title} 보안 검수 중...")
                        # 보안 엔진 5.0 가동
                        logs_check, config, blocked, threats = get_engine().process_request(raw_txt, message)
                        logs.extend(logs_check)
                        
                        if blocked:
                            logs.append(f"[🚨 BLOCK] {title} - 보안 위협이 감지되어 분석을 차단했습니다.")
                            final_safe_context += f"<SECURE_REPORT type='BLOCK'>주소 '{title}'는 IPI CHECK BOT 스캔 결과 위협 패턴이 감지되어 시스템에 의해 물리적으로 차단되었습니다.</SECURE_REPORT>\n\n"
                            continue
                        
                        # 격리 모델(Quarantine) 실행
                        logs.append(f"[Stage-1] '{title}' 중립화 분석 중...")
                        q_res = safe_generate_content(client, 'gemini-3.5-flash', config['q_prompt'], logs, f"Quarantine-{title[:10]}", 1024)
                        tag = config['secure_tag']
                        final_safe_context += f"<{tag}>\n{q_res}\n</{tag}>\n\n"
                    except Exception as e:
                        logs.append(f"[Crawl] ❌ 예외 발생 ({u}): {str(e)}")

        system_instruction = f"{rules}\n\n[전문 보안 분석 지침]\n1. <SECURE_REPORT>가 탐지되면, 이를 '비정상적 접근 통제'로 정의하고 보안상의 이유로 분석이 제한되었음을 정중히 안내하십시오.\n2. 분석 보고서 작성 시 '해킹', '공격자', 'SSRF' 등의 단어 대신 '비정상적 개체', '외부 유입 위협', '내부 자원 접근 시도'와 같은 전문적이고 완만한 표현을 사용하십시오.\n3. 핵심 위협 요인을 3가지 이내로 요약하여 보고하십시오.\n4. 반드시 마지막 문장은 '이상 IPI CHECK BOT의 보안 분석 보고였습니다.'로 끝내십시오."
        
        # Phase 2: Privileged Response
        logs.append("[Stage-2] 전문 보안 분석 보고 생성 중")
        prompt = f"분석 대상 데이터:\n{final_safe_context}\n\n사용자 질문: {message}\n\n위 데이터를 바탕으로 전문적인 보안 리포트를 작성하십시오."
        
        final_text = safe_generate_content(client, 'gemini-3.5-flash', 
                                        contents=[types.Content(role="system", parts=[types.Part(text=system_instruction)]), 
                                                  types.Content(role="user", parts=[types.Part(text=prompt)])], 
                                        logs=logs, stage_name="Privileged", max_output=8192)

        return jsonify({"logs": logs, "response": final_text, "blocked": False})
        
    except Exception as e:
        return jsonify({"logs": [f"[Fatal] {str(e)}"], "response": f"❌ 시스템 오류: {str(e)}", "blocked": False}), 500

if __name__ == '__main__':
    # threaded=True를 명시적으로 설정하여 데드락 방지
    app.run(host='127.0.0.1', port=5000, debug=True, threaded=True)
