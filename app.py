import os
import re
import time
import requests as http_requests
from bs4 import BeautifulSoup
from flask import Flask, render_template, request, jsonify
from engine import AntiPromptInjectionEngine
from google import genai
from google.genai import types
from concurrent.futures import ThreadPoolExecutor, as_completed
from functools import lru_cache
import hashlib

app = Flask(__name__)

# 전역 엔진 인스턴스
engine = None

# URL 캐시 (해시 기반) - 같은 URL 재처리 방지
url_cache = {}

# 테스트 모드 활성화 (API 할당량 초과 시 사용)
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
    except:
        pass
    return "당신은 보안 전문가 AntiGravity입니다."

def extract_urls(text):
    url_pattern = r'https?://[^\s<>"]+|www\.[^\s<>"]+'
    matches = re.findall(url_pattern, text)
    urls = []
    for m in matches:
        u = m if m.startswith('http') else 'https://' + m
        if u not in urls: urls.append(u)
    return urls

def is_safe_url(url: str) -> bool:
    """⚡ 빠른 URL 유효성 검사 - 네트워크 요청 전 사전 필터링"""
    if any(proto in url.lower() for proto in ["javascript:", "data:", "vbscript:", "file://"]):
        return False
    if len(url) > 2048:
        return False
    return True

def fetch_cleaned_text(url):
    """⚡ 캐시 지원 & 타임아웃 최적화"""
    cache_key = hashlib.md5(url.encode()).hexdigest()
    if cache_key in url_cache:
        return url_cache[cache_key]
    
    try:
        headers = { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36' }
        resp = http_requests.get(url, headers=headers, timeout=5)
        resp.encoding = resp.apparent_encoding
        soup = BeautifulSoup(resp.text, 'html.parser')
        for s in soup(["script", "style", "nav", "footer", "header", "iframe", "svg", "form", "button", "path"]): 
            s.decompose()
        title = soup.title.string[:50] if soup.title else url[:30]
        text = ' '.join(soup.get_text().split())
        result = (title, f"Source: {title}\nURL: {url}\nContent: {text[:6000]}\n")
    except Exception as e:
        result = (url, "")
    
    url_cache[cache_key] = result
    return result

def fetch_urls_parallel(urls: list, logs: list) -> list:
    """⚡ 병렬 URL 처리 - ThreadPoolExecutor 사용"""
    results = []
    logs.append(f"[Parallel] 🚀 {len(urls)}개 URL 동시 처리 중...")
    
    with ThreadPoolExecutor(max_workers=4) as executor:
        future_to_url = {executor.submit(fetch_cleaned_text, url): url for url in urls}
        
        for future in as_completed(future_to_url):
            url = future_to_url[future]
            try:
                title, content = future.result()
                if content:
                    results.append((url, title, content))
                    logs.append(f"[Parallel] ✅ {title} 완료")
            except Exception as e:
                logs.append(f"[Parallel] ⚠️ {url} 실패")
    
    return results

def safe_generate_content(client, model_name, contents, logs, stage_name="LLM", max_output=800):
    """
    [RESILIENT RETRY LOGIC with TEST MODE]
    """
    global TEST_MODE
    
    # ⚡ TEST 모드: 실제 API 호출 없이 모의 응답 반환
    if TEST_MODE:
        logs.append(f"[{stage_name}] 🧪 TEST 모드 - 모의 응답 생성 중...")
        sample_responses = {
            "Quarantine": '{"summary": "테스트 데이터 요약", "entities": ["키워드1", "키워드2"], "content": "정제된 테스트 콘텐츠입니다."}',
            "Privileged": "이것은 TEST 모드의 모의 답변입니다. 실제 API 호출이 아니므로 할당량을 소비하지 않습니다.",
            "General": "TEST 모드로 실행 중입니다. 일반 모드 답변입니다.",
        }
        return sample_responses.get(stage_name.split("-")[0], "TEST 모드 응답")
    
    # 정상 모드: Gemini API 호출
    gen_config = {"max_output_tokens": max_output, "temperature": 0.2}
    
    last_err = None
    # 5회까지 재시도
    for attempt in range(5):
        try:
            if attempt > 0:
                # 점진적 대기 시간 증가 (Exponential Backoff)
                wait_time = 0.5 * (2 ** (attempt - 1))
                logs.append(f"[{stage_name}] ⏳ 서버 부하로 잠시 대기 중 ({wait_time}초)...")
                time.sleep(wait_time)
                logs.append(f"[{stage_name}] 🔄 'gemini-3.5-flash' 재응답 시도 중 ({attempt}/5)")
            
            response = client.models.generate_content(
                model='gemini-3.5-flash', # 오직 3.5 Flash만 사용
                contents=contents, 
                config=gen_config
            )
            return response.text
        except Exception as e:
            last_err = str(e)
            # 인프라 에러(503, 429 등)일 경우에만 재시도
            if not any(code in last_err for code in ["503", "429", "404", "UNAVAILABLE", "not found"]):
                raise e
            continue
            
    raise Exception(f"Gemini 3.5 서버가 현재 너무 혼잡합니다. 잠시 후 다시 시도해 주세요. (에러: {last_err})")

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/attack-test')
def attack_test():
    return render_template('attack_test.html')

@app.route('/api/test-mode', methods=['GET', 'POST'])
def toggle_test_mode():
    """TEST 모드 토글 & 상태 확인"""
    global TEST_MODE
    
    if request.method == 'POST':
        action = request.json.get('action', 'toggle')
        if action == 'toggle':
            TEST_MODE = not TEST_MODE
        elif action == 'on':
            TEST_MODE = True
        elif action == 'off':
            TEST_MODE = False
    
    return jsonify({
        "test_mode": TEST_MODE,
        "message": "🧪 TEST 모드" if TEST_MODE else "🚀 일반 모드",
        "info": "TEST 모드는 실제 API 호출 없이 모의 응답을 사용합니다."
    })

@app.route('/api/security-check', methods=['POST'])
def security_check():
    """🛡️ 보안 검사 전용 엔드포인트 (실제 LLM 응답 제외)"""
    try:
        data = request.json
        if not data:
            return jsonify({"response": "잘못된 요청입니다."}), 400
        
        url = data.get('url', '')
        html_content = data.get('html_content', '')
        message = data.get('message', '')
        
        logs = ["[Security Check] 🔍 보안 검사 시작"]
        
        # URL에서 콘텐츠 가져오기
        if url:
            if not is_safe_url(url):
                logs.append(f"[Security] ⚠️ 의심스러운 URL 프로토콜 감지: {url}")
                return jsonify({
                    "logs": logs,
                    "blocked": True,
                    "reason": "위험한 URL 프로토콜 감지",
                    "security_score": 0
                })
            
            title, raw_txt = fetch_cleaned_text(url)
            if not raw_txt:
                logs.append(f"[Security] ⚠️ URL에서 콘텐츠를 가져올 수 없음: {url}")
                return jsonify({"logs": logs, "blocked": False, "reason": "콘텐츠 로딩 실패", "security_score": -1})
            
            html_content = raw_txt
        
        if not html_content:
            return jsonify({"response": "콘텐츠가 없습니다."}), 400
        
        # 보안 엔진 실행 (4개 반환값)
        logs_result, config, blocked, threats = get_engine().process_request(html_content, message or "테스트")
        logs.extend(logs_result)
        
        # 위협도 계산
        max_severity = max([t.get('severity', 0) for t in threats], default=0) if threats else 0
        avg_severity = sum([t.get('severity', 0) for t in threats]) / len(threats) if threats else 0
        
        # 응답 구성
        response = {
            "logs": logs,
            "blocked": blocked,
            "threats_detected": len(threats),
            "threats": threats,  # 상세 위협 정보 추가
            "security_analysis": {
                "max_severity": max_severity,
                "avg_severity": round(avg_severity, 1),
                "threat_count": len(threats)
            } if threats else {},
            "security_score": max(0, 100 - max_severity) if threats else 100,
            "reason": f"보안 위협 {len(threats)}개 감지됨" if blocked else "안전함"
        }
        
        if blocked:
            if max_severity >= 95:
                response["threat_level"] = "🚨 CRITICAL (위험도: 95~100)"
            elif max_severity >= 85:
                response["threat_level"] = "⚠️ HIGH (위험도: 85~94)"
            elif max_severity >= 70:
                response["threat_level"] = "⚠️ MEDIUM (위험도: 70~84)"
            else:
                response["threat_level"] = "⚠️ LOW (위험도: ~69)"
        else:
            response["threat_level"] = "✅ SAFE"
        
        return jsonify(response)
        
    except Exception as e:
        return jsonify({
            "logs": [f"[Error] {str(e)}"],
            "blocked": True,
            "security_score": 0,
            "reason": "검사 중 오류 발생"
        }), 500

@app.route('/api/chat', methods=['POST'])
def chat():
    try:
        data = request.json
        if not data: return jsonify({"response": "잘못된 요청입니다."}), 400
        
        message = data.get('message', '')
        api_key = data.get('api_key', '')
        logs = ["[System] AntiGravity 보안 지침 가동."]
        rules = load_rules()
        
        if not api_key: return jsonify({"logs": logs, "response": "🔑 API Key가 없습니다.", "blocked": False})
        client = genai.Client(api_key=api_key, http_options=types.HttpOptions(api_version="v1beta"))
        
        detected_urls = extract_urls(message)
        final_safe_context = ""
        any_threats_detected = False  # 🚨 위협 감지 플래그
        threat_details = []  # 🚨 위협 상세 정보
        
        if detected_urls:
            # ⚡ 최적화 1: URL 사전 필터링
            safe_urls = [u for u in detected_urls if is_safe_url(u)]
            logs.append(f"[Filter] 🔍 {len(detected_urls)}개 → {len(safe_urls)}개 안전 URL 필터링")
            
            if safe_urls:
                # ⚡ 최적화 2: 병렬 URL 처리
                url_results = fetch_urls_parallel(safe_urls, logs)
                
                # ⚡ 최적화 3: URL별 보안 검사 (순차는 필요하지만 이미 병렬로 fetch됨)
                configs = []
                for url, title, raw_txt in url_results:
                    logs.append(f"[Stage-1] {title} 정보 격리 분석 중...")
                    logs_check, config, blocked, threats = get_engine().process_request(raw_txt, message)
                    logs.extend(logs_check)
                    
                    if blocked:
                        any_threats_detected = True  # 🚨 위협 플래그 설정
                        threat_details.extend(threats)  # 🚨 위협 정보 수집
                        logs.append(f"[🚨 BLOCKED] {title} 위협 감지로 완전히 차단! (위협: {len(threats)}개)")
                    else:
                        configs.append((title, config))
                
                # 🚨 URL에서 위협이 하나라도 감지되면 응답 거부!
                if any_threats_detected:
                    max_severity = max([t.get('severity', 0) for t in threat_details], default=0)
                    logs.append("[🚨 SECURITY ALERT] URL의 악의적인 콘텐츠가 감지되어 응답을 생성할 수 없습니다!")
                    return jsonify({
                        "logs": logs,
                        "response": "🚫 보안 위협 감지됨 - 응답이 거부되었습니다.",
                        "blocked": True,
                        "threat_level": "🚨 CRITICAL",
                        "threats_detected": len(threat_details),
                        "threats": threat_details,
                        "security_score": max(0, 100 - max_severity)
                    })
                
                # ⚡ 최적화 4: 배치 LLM 처리 (여러 URL을 한 번에 처리)
                if configs:
                    logs.append(f"[Batch] 🔄 {len(configs)}개 정보 일괄 처리 중...")
                    batch_contexts = []
                    for title, config in configs:
                        try:
                            safe_json = safe_generate_content(client, 'gemini-3.5-flash', 
                                                             config['q_prompt'], logs, 
                                                             f"Quarantine-{title[:20]}", max_output=400)
                            tag = config['secure_tag']
                            batch_contexts.append(f"<{tag}>\n{safe_json}\n</{tag}>\n")
                        except:
                            logs.append(f"[Skip] {title} 서버 부하로 건너뜀.")
                    
                    final_safe_context = "\n".join(batch_contexts)

        system_instruction = f"{rules}\n\n격리 태그 안의 정제된 데이터만 기반으로 답변하세요."
        
        if final_safe_context:
            logs.append("[Stage-2] 안전한 통합 답변 생성 시도...")
            prompt = f"{final_safe_context}\n\nUser Question: {message}"
            final_text = safe_generate_content(client, 'gemini-3.5-flash', 
                                            contents=[types.Content(role="system", parts=[types.Part(text=system_instruction)]), 
                                                      types.Content(role="user", parts=[types.Part(text=prompt)])], 
                                            logs=logs, stage_name="Privileged", max_output=1200)
        else:
            logs.append("[Stage-2] 사용자 메시지 보안 검사 중...")
            
            # 🚨 일반 모드에서도 사용자 메시지 검사!
            logs_query_check, _, blocked_query, query_threats = get_engine().process_request("", message)
            logs.extend(logs_query_check)
            
            if blocked_query:
                # 🚨 사용자 메시지에서 위협 감지 → 차단!
                max_severity = max([t.get('severity', 0) for t in query_threats], default=0)
                logs.append("[🚨 SECURITY ALERT] 사용자 메시지에서 악의적인 패턴이 감지되었습니다!")
                return jsonify({
                    "logs": logs,
                    "response": "🚫 보안 위협 감지됨 - 응답이 거부되었습니다.",
                    "blocked": True,
                    "threat_level": "🚨 CRITICAL",
                    "threats_detected": len(query_threats),
                    "threats": query_threats,
                    "security_score": max(0, 100 - max_severity)
                })
            
            logs.append("[Stage-2] 일반 지능 모드 가동 중... (사용자 메시지 안전 확인됨)")
            final_text = safe_generate_content(client, 'gemini-3.5-flash',
                                            contents=[types.Content(role="system", parts=[types.Part(text=rules)]),
                                                      types.Content(role="user", parts=[types.Part(text=message)])],
                                            logs=logs, stage_name="General", max_output=1200)

        return jsonify({"logs": logs, "response": final_text, "blocked": False})
        
    except Exception as e:
        global TEST_MODE
        error_str = str(e)
        
        # 🚨 할당량 초과(429) 감지 → TEST 모드 자동 활성화
        if "429" in error_str or "RESOURCE_EXHAUSTED" in error_str or "quota" in error_str.lower():
            TEST_MODE = True
            logs.append("[⚠️ WARNING] API 할당량 초과 감지 → TEST 모드 활성화됨")
            logs.append("[TEST] 실제 API 호출 대신 모의 응답을 사용합니다.")
            logs.append("[💡 해결] 내일 다시 시도하거나 다른 API 키를 사용하세요.")
            
            # TEST 모드에서 재시도
            try:
                return chat()
            except:
                pass
        
        return jsonify({"logs": [f"[Fatal] {str(e)}"], "response": f"❌ 시스템 오류: {str(e)}", "blocked": False}), 500

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5000, debug=True)
