
from bs4 import BeautifulSoup, Comment
from pathlib import Path
from urllib.parse import urlparse
import requests
import sys
import re


# =========================
# 1. 키워드 사전
# =========================

GAMBLING_STRONG = [
    "카지노", "바카라", "슬롯", "토토", "사설토토", "스포츠토토",
    "스포츠베팅", "스포츠배팅", "먹튀", "꽁머니", "홀덤"
]

GAMBLING_MEDIUM = [
    "베팅", "배팅", "배당", "첫충", "매충", "롤링", "충전", "환전",
    "보증업체", "안전놀이터", "놀이터"
]

STREAMING_STRONG = [
    "무료중계", "실시간중계", "스포츠중계", "해외축구중계",
    "nba중계", "mlb중계", "ufc중계", "불법중계",
    "영화무료보기", "드라마무료보기", "티비다시보기"
]

STREAMING_MEDIUM = [
    "다시보기", "고화질중계", "라이브중계", "중계사이트"
]

# 정상 사이트에도 나올 수 있지만, 난독화/리다이렉트 판단에 참고할 JS 패턴
SUSPICIOUS_JS_PATTERNS = [
    r"\beval\s*\(",
    r"\batob\s*\(",
    r"\bunescape\s*\(",
    r"document\s*\.\s*write\s*\(",
    r"String\s*\.\s*fromCharCode\s*\(",
    r"location\s*\.\s*href\s*=",
    r"window\s*\.\s*location\s*=",
    r"setTimeout\s*\(\s*['\"]",
    r"setInterval\s*\(\s*['\"]",
]

SHORTENER_OR_MESSENGER_DOMAINS = [
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd",
    "telegram.me", "t.me", "open.kakao.com"
]


# =========================
# 2. HTML 불러오기
# =========================

def load_html(source):
    if source.startswith("http://") or source.startswith("https://"):
        headers = {
            "User-Agent": (
                "Mozilla/5.0 (compatible; DOM-Analysis-Student-Project/1.0)"
            )
        }
        response = requests.get(source, headers=headers, timeout=12)
        response.raise_for_status()
        return response.text

    return Path(source).read_text(encoding="utf-8")


# =========================
# 3. 전처리 함수
# =========================

def remove_js_comments(js_text):
    # /* ... */ 주석 제거
    js_text = re.sub(r"/\*.*?\*/", " ", js_text, flags=re.DOTALL)
    # // 주석 제거
    js_text = re.sub(r"//.*", " ", js_text)
    return js_text


def get_visible_text(soup):
    cloned = BeautifulSoup(str(soup), "html.parser")

    for tag in cloned(["script", "style", "noscript", "svg", "template"]):
        tag.decompose()

    for comment in cloned.find_all(string=lambda text: isinstance(text, Comment)):
        comment.extract()

    return cloned.get_text(" ", strip=True)


def get_dom_depth(tag, depth=0):
    children = [
        child for child in getattr(tag, "children", [])
        if getattr(child, "name", None)
    ]

    if not children:
        return depth

    return max(get_dom_depth(child, depth + 1) for child in children)


def count_event_attrs(soup):
    count = 0

    for tag in soup.find_all(True):
        for attr in tag.attrs:
            if attr.lower().startswith("on"):
                count += 1

    return count


def count_keywords(text, keywords):
    count = 0
    found = {}

    normalized_text = text.lower().replace(" ", "")

    for keyword in keywords:
        normalized_keyword = keyword.lower().replace(" ", "")
        keyword_count = normalized_text.count(normalized_keyword)

        if keyword_count > 0:
            found[keyword] = keyword_count
            count += keyword_count

    return count, found


def get_domain(url):
    if not url.startswith("http://") and not url.startswith("https://"):
        return ""

    parsed = urlparse(url)
    return parsed.netloc.lower()


def extract_external_domains(soup, base_domain):
    domains = []

    for link in soup.find_all("a"):
        href = link.get("href", "")

        if href.startswith("http://") or href.startswith("https://"):
            domain = urlparse(href).netloc.lower()

            if domain and domain != base_domain:
                domains.append(domain)

    return domains


def is_hidden_tag(tag):
    style = tag.get("style", "").replace(" ", "").lower()
    hidden_attr = tag.get("hidden") is not None

    if hidden_attr:
        return True

    if "display:none" in style or "visibility:hidden" in style:
        return True

    return False


def count_hidden_keyword_blocks(soup):
    hidden_text = []

    all_keywords = (
        GAMBLING_STRONG
        + GAMBLING_MEDIUM
        + STREAMING_STRONG
        + STREAMING_MEDIUM
    )

    for tag in soup.find_all(True):
        if is_hidden_tag(tag):
            hidden_text.append(tag.get_text(" ", strip=True))

    text = " ".join(hidden_text)
    count, found = count_keywords(text, all_keywords)

    return count, found


# =========================
# 4. 분석 함수
# =========================

def analyze_html(html, source):
    soup = BeautifulSoup(html, "html.parser")
    base_domain = get_domain(source)

    visible_text = get_visible_text(soup)
    title_text = soup.title.get_text(" ", strip=True) if soup.title else ""

    scripts = soup.find_all("script")
    inline_script_text = " ".join(
        script.get_text(" ", strip=True)
        for script in scripts
        if not script.get("src")
    )
    inline_script_text = remove_js_comments(inline_script_text)

    links = soup.find_all("a")
    external_domains = extract_external_domains(soup, base_domain)
    unique_external_domains = sorted(set(external_domains))

    iframe_tags = soup.find_all("iframe")
    form_tags = soup.find_all("form")
    input_tags = soup.find_all("input")

    gambling_strong_count, gambling_strong_found = count_keywords(
        visible_text, GAMBLING_STRONG
    )
    gambling_medium_count, gambling_medium_found = count_keywords(
        visible_text, GAMBLING_MEDIUM
    )
    streaming_strong_count, streaming_strong_found = count_keywords(
        visible_text, STREAMING_STRONG
    )
    streaming_medium_count, streaming_medium_found = count_keywords(
        visible_text, STREAMING_MEDIUM
    )

    title_keyword_count, title_keywords = count_keywords(
        title_text,
        GAMBLING_STRONG + STREAMING_STRONG
    )

    url_keyword_count, url_keywords = count_keywords(
        source,
        GAMBLING_STRONG + STREAMING_STRONG + ["casino", "toto", "bet", "live"]
    )

    suspicious_js_count = 0
    for pattern in SUSPICIOUS_JS_PATTERNS:
        suspicious_js_count += len(
            re.findall(pattern, inline_script_text, flags=re.IGNORECASE)
        )

    hidden_keyword_count, hidden_keywords = count_hidden_keyword_blocks(soup)

    shortener_count = 0
    for domain in unique_external_domains:
        for suspicious_domain in SHORTENER_OR_MESSENGER_DOMAINS:
            if domain == suspicious_domain or domain.endswith("." + suspicious_domain):
                shortener_count += 1

    password_input_count = len([
        input_tag for input_tag in input_tags
        if input_tag.get("type", "").lower() == "password"
    ])

    features = {
        "iframe_count": len(iframe_tags),
        "script_count": len(scripts),
        "inline_script_count": len([s for s in scripts if not s.get("src")]),
        "link_count": len(links),
        "external_link_count": len(external_domains),
        "unique_external_domain_count": len(unique_external_domains),
        "form_count": len(form_tags),
        "button_count": len(soup.find_all("button")),
        "image_count": len(soup.find_all("img")),
        "input_count": len(input_tags),
        "password_input_count": password_input_count,
        "dom_depth": get_dom_depth(soup),
        "event_attr_count": count_event_attrs(soup),
        "gambling_strong_count": gambling_strong_count,
        "gambling_medium_count": gambling_medium_count,
        "streaming_strong_count": streaming_strong_count,
        "streaming_medium_count": streaming_medium_count,
        "title_keyword_count": title_keyword_count,
        "url_keyword_count": url_keyword_count,
        "hidden_keyword_count": hidden_keyword_count,
        "suspicious_js_count": suspicious_js_count,
        "shortener_or_messenger_domain_count": shortener_count,
    }

    found_keywords = {
        "도박 강한 키워드": gambling_strong_found,
        "도박 보조 키워드": gambling_medium_found,
        "스트리밍 강한 키워드": streaming_strong_found,
        "스트리밍 보조 키워드": streaming_medium_found,
        "제목 키워드": title_keywords,
        "URL 키워드": url_keywords,
        "숨김 키워드": hidden_keywords,
    }

    score, evidence_categories, evidence_messages = calculate_score(features)

    label, label_explanation = classify(score, features, evidence_categories)

    return {
        "source": source,
        "features": features,
        "score": score,
        "label": label,
        "label_explanation": label_explanation,
        "evidence_categories": evidence_categories,
        "evidence_messages": evidence_messages,
        "found_keywords": found_keywords,
        "unique_external_domains": unique_external_domains[:12],
    }


# =========================
# 5. 점수 계산
# =========================

def calculate_score(f):
    score = 0
    evidence_categories = set()
    evidence_messages = []

    # A. 키워드: 가장 중요한 근거
    keyword_score = 0
    keyword_score += min(f["gambling_strong_count"] * 12, 36)
    keyword_score += min(f["gambling_medium_count"] * 4, 16)
    keyword_score += min(f["streaming_strong_count"] * 10, 30)
    keyword_score += min(f["streaming_medium_count"] * 3, 9)

    if keyword_score > 0:
        evidence_categories.add("의심 키워드")
        evidence_messages.append(f"의심 키워드 기반 점수 {keyword_score}점")

    score += keyword_score

    # B. 제목/URL에 직접적인 의심 표현
    title_url_score = 0

    if f["title_keyword_count"] > 0:
        title_url_score += 10

    if f["url_keyword_count"] > 0:
        title_url_score += 10

    if title_url_score > 0:
        evidence_categories.add("제목/URL")
        evidence_messages.append(f"제목 또는 URL에서 의심 표현 발견 +{title_url_score}점")

    score += title_url_score

    # C. 숨김 텍스트에 의심 키워드가 있으면 강한 근거
    if f["hidden_keyword_count"] > 0:
        hidden_score = min(f["hidden_keyword_count"] * 8, 20)
        score += hidden_score
        evidence_categories.add("숨김 텍스트")
        evidence_messages.append(f"숨겨진 영역에서 의심 키워드 발견 +{hidden_score}점")

    # D. iframe: 단독으로는 거의 점수를 주지 않음
    iframe_score = 0

    if f["iframe_count"] >= 5:
        iframe_score += 8
    elif f["iframe_count"] >= 2 and (
        f["streaming_strong_count"] > 0 or f["streaming_medium_count"] > 0
    ):
        iframe_score += 8
    elif f["iframe_count"] >= 1 and f["streaming_strong_count"] > 0:
        iframe_score += 4

    if iframe_score > 0:
        score += iframe_score
        evidence_categories.add("iframe 구조")
        evidence_messages.append(f"iframe 구조가 의심 문맥과 함께 발견 +{iframe_score}점")

    # E. script: 개수가 많다는 이유만으로 거의 점수를 주지 않음
    script_score = 0

    if f["script_count"] >= 120:
        script_score += 6
    elif f["script_count"] >= 80:
        script_score += 3

    if script_score > 0:
        score += script_score
        evidence_categories.add("과도한 스크립트")
        evidence_messages.append(f"script 태그가 매우 많음 +{script_score}점")

    # F. 의심 JS: 키워드가 없으면 낮게 제한
    js_score_raw = min(f["suspicious_js_count"] * 5, 20)

    has_content_evidence = (
        f["gambling_strong_count"]
        + f["gambling_medium_count"]
        + f["streaming_strong_count"]
        + f["streaming_medium_count"]
        + f["title_keyword_count"]
        + f["url_keyword_count"]
    ) > 0

    if not has_content_evidence:
        js_score = min(js_score_raw, 6)
    else:
        js_score = js_score_raw

    if js_score > 0:
        score += js_score
        evidence_categories.add("의심 JavaScript")
        evidence_messages.append(f"의심 JavaScript 패턴 발견 +{js_score}점")

    # G. 링크 구조: 외부 링크가 많아도 단독으로는 낮은 점수
    link_score = 0

    if f["unique_external_domain_count"] >= 12:
        link_score += 6
    elif f["unique_external_domain_count"] >= 8:
        link_score += 3

    if f["external_link_count"] >= 50:
        link_score += 5

    if f["link_count"] >= 20:
        ratio = f["external_link_count"] / max(f["link_count"], 1)
        if ratio >= 0.75:
            link_score += 5

    if f["shortener_or_messenger_domain_count"] > 0:
        link_score += min(f["shortener_or_messenger_domain_count"] * 5, 10)

    if link_score > 0:
        score += link_score
        evidence_categories.add("외부 링크 패턴")
        evidence_messages.append(f"외부 링크 패턴에서 의심 요소 +{link_score}점")

    # H. 입력 구조: 로그인/가입/문의 구조도 단독으로는 낮게
    input_score = 0

    if f["password_input_count"] > 0:
        input_score += 4

    if f["form_count"] >= 3:
        input_score += 4

    if (
        f["input_count"] >= 5
        and (f["gambling_medium_count"] > 0 or f["gambling_strong_count"] > 0)
    ):
        input_score += 6

    if input_score > 0:
        score += input_score
        evidence_categories.add("입력 양식")
        evidence_messages.append(f"입력 양식 구조 발견 +{input_score}점")

    # I. 이벤트 속성 / DOM 깊이: 보조 지표만
    structure_score = 0

    if f["event_attr_count"] >= 20:
        structure_score += 6
    elif f["event_attr_count"] >= 8:
        structure_score += 3

    if f["dom_depth"] >= 28:
        structure_score += 4
    elif f["dom_depth"] >= 22:
        structure_score += 2

    if structure_score > 0:
        score += structure_score
        evidence_categories.add("복잡한 DOM/이벤트")
        evidence_messages.append(f"DOM 또는 이벤트 속성 복잡도 +{structure_score}점")

    return min(score, 100), evidence_categories, evidence_messages


# =========================
# 6. 최종 분류
# =========================

def classify(score, f, evidence_categories):
    keyword_total = (
        f["gambling_strong_count"]
        + f["gambling_medium_count"]
        + f["streaming_strong_count"]
        + f["streaming_medium_count"]
        + f["title_keyword_count"]
        + f["url_keyword_count"]
        + f["hidden_keyword_count"]
    )

    strong_keyword_total = (
        f["gambling_strong_count"]
        + f["streaming_strong_count"]
        + f["title_keyword_count"]
        + f["url_keyword_count"]
    )

    evidence_count = len(evidence_categories)

    # 핵심 개선점:
    # 점수만 높다고 바로 의심 높음으로 분류하지 않는다.
    # 강한 키워드/URL/숨김 텍스트 같은 핵심 근거와 복수의 보조 근거가 필요하다.
    if (
        score >= 70
        and strong_keyword_total >= 2
        and evidence_count >= 2
    ):
        return (
            "의심 높음",
            "의심 키워드와 구조적 특징이 함께 발견되어 추가 확인이 필요합니다."
        )

    if (
        score >= 45
        and keyword_total >= 2
        and evidence_count >= 2
    ):
        return (
            "의심 보통",
            "일부 의심 요소가 있으나, 단정하지 말고 추가 검토가 필요합니다."
        )

    if (
        score >= 35
        and strong_keyword_total >= 1
    ):
        return (
            "의심 보통",
            "강한 의심 키워드가 일부 발견되었습니다."
        )

    return (
        "의심 낮음",
        "불법 도박/스트리밍 사이트로 볼 핵심 근거가 부족합니다."
    )


# =========================
# 7. 한글 출력
# =========================

def print_report(result):
    f = result["features"]

    print()
    print("=" * 64)
    print("정밀 DOM 기반 웹페이지 의심도 분석 결과")
    print("=" * 64)
    print(f"분석 대상: {result['source']}")
    print(f"최종 점수: {result['score']}점 / 100점")
    print(f"판정 결과: {result['label']}")
    print(f"해석: {result['label_explanation']}")
    print("-" * 64)

    print("세부 분석 항목")
    print("-" * 64)
    print(f"iframe 태그 수                   : {f['iframe_count']}개")
    print(f"script 태그 수                   : {f['script_count']}개")
    print(f"inline script 태그 수            : {f['inline_script_count']}개")
    print(f"a 링크 태그 수                   : {f['link_count']}개")
    print(f"외부 링크 수                     : {f['external_link_count']}개")
    print(f"외부 도메인 종류 수              : {f['unique_external_domain_count']}개")
    print(f"form 태그 수                     : {f['form_count']}개")
    print(f"button 태그 수                   : {f['button_count']}개")
    print(f"img 이미지 태그 수               : {f['image_count']}개")
    print(f"input 입력창 수                  : {f['input_count']}개")
    print(f"password 입력창 수               : {f['password_input_count']}개")
    print(f"DOM 최대 깊이                    : {f['dom_depth']}단계")
    print(f"onclick/onload 이벤트 속성 수     : {f['event_attr_count']}개")
    print(f"도박 강한 키워드 수              : {f['gambling_strong_count']}개")
    print(f"도박 보조 키워드 수              : {f['gambling_medium_count']}개")
    print(f"스트리밍 강한 키워드 수          : {f['streaming_strong_count']}개")
    print(f"스트리밍 보조 키워드 수          : {f['streaming_medium_count']}개")
    print(f"제목/URL 의심 키워드 수          : {f['title_keyword_count'] + f['url_keyword_count']}개")
    print(f"숨김 영역 의심 키워드 수         : {f['hidden_keyword_count']}개")
    print(f"의심 JavaScript 패턴 수           : {f['suspicious_js_count']}개")
    print(f"단축 URL/메신저 도메인 수         : {f['shortener_or_messenger_domain_count']}개")

    print("-" * 64)
    print("판정에 반영된 근거")
    print("-" * 64)

    if result["evidence_messages"]:
        for message in result["evidence_messages"]:
            print(f"- {message}")
    else:
        print("- 뚜렷한 의심 근거가 발견되지 않았습니다.")

    print("-" * 64)
    print("발견된 의심 키워드")
    print("-" * 64)

    any_keyword = False

    for category, words in result["found_keywords"].items():
        if words:
            any_keyword = True
            word_list = ", ".join(
                f"{word}({count})" for word, count in words.items()
            )
            print(f"- {category}: {word_list}")

    if not any_keyword:
        print("- 발견된 의심 키워드가 없습니다.")

    print("-" * 64)
    print("외부 도메인 예시")
    print("-" * 64)

    if result["unique_external_domains"]:
        for domain in result["unique_external_domains"]:
            print(f"- {domain}")
    else:
        print("- 외부 도메인이 거의 없거나 확인되지 않았습니다.")

    print("=" * 64)
    print()


# =========================
# 8. 실행
# =========================

def main():
    if len(sys.argv) < 2:
        print("사용법:")
        print("python dom_detector_precise.py normal_sample.html")
        print("python dom_detector_precise.py mock_illegal_site_sample.html")
        print("python dom_detector_precise.py https://example.com")
        return

    source = sys.argv[1]

    try:
        html = load_html(source)
        result = analyze_html(html, source)
        print_report(result)

    except requests.exceptions.RequestException as e:
        print("웹사이트를 불러오는 중 오류가 발생했습니다.")
        print(e)

    except FileNotFoundError:
        print("파일을 찾을 수 없습니다.")

    except UnicodeDecodeError:
        print("파일 인코딩 문제가 발생했습니다. HTML 파일을 UTF-8로 저장해 주세요.")

    except Exception as e:
        print("분석 중 오류가 발생했습니다.")
        print(e)


if __name__ == "__main__":
    main()
