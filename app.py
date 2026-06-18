from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass
from typing import Any
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup
from bs4.element import Tag
from flask import Flask, render_template, request

from dom_detector_precise import analyze_html


app = Flask(__name__)

# 너무 큰 HTML을 무작정 가져오지 않기 위한 제한
MAX_HTML_BYTES = 3 * 1024 * 1024  # 3MB
REQUEST_TIMEOUT = 12
MAX_REDIRECTS = 6

# DOM 시각화는 너무 큰 페이지에서 브라우저가 느려지지 않도록 일부만 보여준다.
MAX_TREE_DEPTH = 7
MAX_TREE_NODES = 380
IMPORTANT_TAGS = {
    "iframe", "script", "form", "input", "button", "a",
    "video", "embed", "object", "main", "section", "article",
    "header", "nav", "footer"
}



class UrlValidationError(ValueError):
    """사용자에게 보여줄 수 있는 URL/요청 관련 오류."""


@dataclass
class FetchMeta:
    final_url: str
    status_code: int
    content_type: str
    html_size_kb: float
    redirect_count: int
    redirect_chain: list[str]
    server: str

    def to_template_dict(self) -> dict[str, Any]:
        return {
            "final_url": self.final_url,
            "status_code": self.status_code,
            "content_type": self.content_type,
            "html_size_kb": self.html_size_kb,
            "redirect_count": self.redirect_count,
            "redirect_chain": self.redirect_chain,
            "server": self.server,
        }


def is_private_or_local_host(hostname: str) -> bool:
    """localhost, 내부망 IP, 루프백 주소 등을 차단한다."""
    if not hostname:
        return True

    lowered = hostname.lower().strip().rstrip(".")

    if lowered in {"localhost", "0.0.0.0"} or lowered.endswith(".local"):
        return True

    try:
        ip_direct = ipaddress.ip_address(lowered)
        return is_blocked_ip(ip_direct)
    except ValueError:
        pass

    try:
        infos = socket.getaddrinfo(lowered, None)
    except socket.gaierror as exc:
        raise UrlValidationError(
            "도메인 주소를 확인할 수 없습니다. 주소가 정확한지 확인해 주세요."
        ) from exc

    for info in infos:
        ip_text = info[4][0]
        try:
            ip = ipaddress.ip_address(ip_text)
        except ValueError:
            continue

        if is_blocked_ip(ip):
            return True

    return False


def is_blocked_ip(ip: ipaddress._BaseAddress) -> bool:
    """SSRF 방지를 위해 내부망/특수 목적 IP 차단."""
    return bool(
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )


def validate_url(raw_url: str) -> str:
    """사용자가 입력한 URL을 정리하고 기본적인 보안 검사를 수행한다."""
    url = raw_url.strip()

    if not url:
        raise UrlValidationError("URL을 입력해 주세요.")

    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    parsed = urlparse(url)

    if parsed.scheme not in {"http", "https"}:
        raise UrlValidationError("http 또는 https 주소만 분석할 수 있습니다.")

    if not parsed.netloc or not parsed.hostname:
        raise UrlValidationError("올바른 웹사이트 주소를 입력해 주세요.")

    if is_private_or_local_host(parsed.hostname):
        raise UrlValidationError(
            "보안상 localhost, 내부망, 사설 IP 주소는 분석할 수 없습니다."
        )

    return url


def build_headers() -> dict[str, str]:
    """
    일반 브라우저와 비슷한 기본 헤더.
    차단 우회 목적이 아니라, 정상 HTML 응답을 받기 위한 기본 요청 헤더다.
    """
    return {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/125.0 Safari/537.36 DOM-Analysis-Student-Project/1.0"
        ),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "ko-KR,ko;q=0.9,en-US;q=0.7,en;q=0.6",
        "Connection": "close",
    }


def make_error_message(exc: requests.exceptions.RequestException) -> str:
    """requests 예외를 학생이 이해하기 쉬운 한글 문장으로 바꾼다."""
    if isinstance(exc, requests.exceptions.Timeout):
        return (
            "웹사이트 응답 시간이 너무 오래 걸립니다. 서버가 느리거나, "
            "자동 요청을 제한하고 있을 수 있습니다."
        )

    if isinstance(exc, requests.exceptions.SSLError):
        return (
            "SSL 인증서 또는 보안 연결 문제로 웹사이트를 불러오지 못했습니다. "
            "브라우저에서는 열려도 Python requests에서는 차단될 수 있습니다."
        )

    if isinstance(exc, requests.exceptions.ConnectionError):
        return (
            "서버에 연결하지 못했습니다. 도메인 차단, DNS 문제, 서버 불안정, "
            "학교/통신사 네트워크 차단 가능성이 있습니다."
        )

    return f"웹사이트를 불러오지 못했습니다. 원인: {exc}"


def explain_status_code(status_code: int) -> str:
    """HTTP 상태 코드를 사람이 읽기 쉬운 설명으로 변환한다."""
    if status_code == 403:
        return (
            "서버가 요청을 거부했습니다(403). 브라우저 접속은 허용하지만 "
            "Python 같은 자동 요청은 막는 사이트일 수 있습니다."
        )
    if status_code == 404:
        return "페이지를 찾을 수 없습니다(404). 주소가 바뀌었거나 삭제되었을 수 있습니다."
    if status_code == 429:
        return "요청이 너무 많다고 판단되어 차단되었습니다(429)."
    if status_code in {500, 502, 503, 504}:
        return "서버 내부 오류 또는 일시적 장애가 발생했습니다."
    if 300 <= status_code < 400:
        return "리다이렉트 응답입니다. 이동할 주소를 확인해야 합니다."
    if 400 <= status_code < 500:
        return "클라이언트 요청을 서버가 처리하지 못했습니다."
    if 500 <= status_code < 600:
        return "서버 측 문제로 요청이 실패했습니다."
    return "정상 HTML 응답이 아닙니다."


def fetch_html(url: str) -> tuple[str, dict[str, Any]]:
    """
    URL에서 HTML을 가져온다.

    개선점
    - 리다이렉트를 직접 따라가며 각 이동 주소를 검증한다.
    - HTTP 403/404/429/500 등을 구분해서 보여준다.
    - 너무 큰 HTML은 중단한다.
    - text/html이 아니어도 일부 사이트의 잘못된 Content-Type을 고려해 앞부분을 검사한다.
    """
    session = requests.Session()
    session.headers.update(build_headers())

    current_url = validate_url(url)
    redirect_chain: list[str] = []
    response: requests.Response | None = None

    for redirect_index in range(MAX_REDIRECTS + 1):
        try:
            response = session.get(
                current_url,
                timeout=REQUEST_TIMEOUT,
                allow_redirects=False,
                stream=True,
            )
        except requests.exceptions.RequestException as exc:
            raise UrlValidationError(make_error_message(exc)) from exc

        # 3xx 리다이렉트는 직접 처리해서 최종 주소도 검사한다.
        if 300 <= response.status_code < 400:
            location = response.headers.get("Location")
            if not location:
                raise UrlValidationError(
                    f"리다이렉트 응답({response.status_code})이지만 이동할 주소가 없습니다."
                )

            next_url = urljoin(current_url, location)
            next_url = validate_url(next_url)
            redirect_chain.append(next_url)
            current_url = next_url

            if redirect_index >= MAX_REDIRECTS:
                raise UrlValidationError(
                    f"리다이렉트가 {MAX_REDIRECTS}회를 초과하여 분석을 중단했습니다. "
                    "주소 변경이 반복되는 사이트일 수 있습니다."
                )

            continue

        break

    if response is None:
        raise UrlValidationError("웹사이트 응답을 받지 못했습니다.")

    status_code = response.status_code

    if status_code >= 400:
        raise UrlValidationError(
            f"웹사이트를 불러올 수 없습니다. HTTP 상태 코드: {status_code}. "
            f"{explain_status_code(status_code)}"
        )

    content_type = response.headers.get("Content-Type", "확인 어려움")
    server = response.headers.get("Server", "확인 어려움")

    chunks: list[bytes] = []
    total = 0

    try:
        for chunk in response.iter_content(chunk_size=8192):
            if not chunk:
                continue

            total += len(chunk)
            if total > MAX_HTML_BYTES:
                raise UrlValidationError(
                    "HTML 크기가 너무 커서 분석을 중단했습니다. 현재 버전은 3MB까지만 분석합니다."
                )

            chunks.append(chunk)
    except requests.exceptions.RequestException as exc:
        raise UrlValidationError(make_error_message(exc)) from exc

    raw_bytes = b"".join(chunks)

    if not raw_bytes:
        raise UrlValidationError("서버 응답은 성공했지만 HTML 내용이 비어 있습니다.")

    response.encoding = response.encoding or response.apparent_encoding or "utf-8"
    html = raw_bytes.decode(response.encoding, errors="replace")

    # Content-Type이 이상해도 실제 내용이 HTML이면 분석 허용.
    html_preview = html[:500].lower()
    looks_like_html = "<html" in html_preview or "<!doctype html" in html_preview
    content_type_lower = content_type.lower()
    is_declared_html = (
        "text/html" in content_type_lower
        or "application/xhtml" in content_type_lower
        or "확인 어려움" in content_type
    )

    if not is_declared_html and not looks_like_html:
        raise UrlValidationError(
            f"HTML 문서가 아닌 응답입니다. Content-Type: {content_type}. "
            "PDF, 이미지, 영상 파일, JSON 응답은 DOM 분석 대상이 아닙니다."
        )

    meta = FetchMeta(
        final_url=response.url,
        status_code=status_code,
        content_type=content_type,
        html_size_kb=round(len(raw_bytes) / 1024, 1),
        redirect_count=len(redirect_chain),
        redirect_chain=redirect_chain,
        server=server,
    )

    return html, meta.to_template_dict()



def shorten(value: str, max_len: int = 70) -> str:
    """DOM 시각화에서 속성값이 너무 길어지지 않게 줄인다."""
    value = " ".join(str(value).split())
    if len(value) <= max_len:
        return value
    return value[: max_len - 1] + "…"


def summarize_tag_attributes(tag: Tag) -> str:
    """태그의 핵심 속성만 골라 사람이 읽기 쉽게 요약한다."""
    parts: list[str] = []

    if tag.get("id"):
        parts.append(f"id=\"{shorten(tag.get('id'), 34)}\"")

    class_value = tag.get("class")
    if class_value:
        class_text = " ".join(class_value[:4]) if isinstance(class_value, list) else str(class_value)
        parts.append(f"class=\"{shorten(class_text, 44)}\"")

    for attr in ["type", "name", "placeholder", "title", "aria-label"]:
        if tag.get(attr):
            parts.append(f"{attr}=\"{shorten(tag.get(attr), 38)}\"")

    for attr in ["href", "src", "action"]:
        raw = tag.get(attr)
        if raw:
            parsed = urlparse(raw)
            if parsed.netloc:
                value = parsed.netloc
            else:
                value = shorten(raw, 44)
            parts.append(f"{attr}=\"{value}\"")

    # 이벤트 속성은 의심 구조를 설명하기 위해 이름만 표시한다.
    event_attrs = [attr for attr in tag.attrs if attr.lower().startswith("on")]
    if event_attrs:
        parts.append("events=" + ",".join(event_attrs[:4]))

    if is_visual_hidden(tag):
        parts.append("hidden")

    return " ".join(parts[:7])


def is_visual_hidden(tag: Tag) -> bool:
    style = tag.get("style", "")
    style = "".join(str(style).lower().split())
    return bool(tag.get("hidden") is not None or "display:none" in style or "visibility:hidden" in style)


def classify_dom_node(tag: Tag) -> tuple[str, str]:
    """DOM 트리에서 강조할 노드 유형을 정한다."""
    name = tag.name.lower()
    event_count = sum(1 for attr in tag.attrs if attr.lower().startswith("on"))

    if is_visual_hidden(tag):
        return "risk", "숨김 영역"

    if event_count:
        return "risk", f"이벤트 속성 {event_count}개"

    if name in {"iframe", "embed", "object"}:
        return "watch", "삽입 프레임"

    if name == "script":
        return "watch", "스크립트"

    if name in {"form", "input"}:
        return "watch", "입력 구조"

    if name == "a" and tag.get("href", "").startswith(("http://", "https://")):
        return "link", "외부 링크"

    if name in {"header", "nav", "main", "section", "article", "footer"}:
        return "layout", "레이아웃"

    return "normal", ""


def build_dom_tree_node(tag: Tag, depth: int, counter: dict[str, Any]) -> dict[str, Any] | None:
    """BeautifulSoup Tag를 템플릿에서 그릴 수 있는 작은 dict 트리로 변환한다."""
    if counter["count"] >= MAX_TREE_NODES:
        counter["truncated"] = True
        return None

    counter["count"] += 1
    risk_class, note = classify_dom_node(tag)

    node: dict[str, Any] = {
        "tag": tag.name,
        "attrs": summarize_tag_attributes(tag),
        "risk_class": risk_class,
        "note": note,
        "depth": depth,
        "children": [],
    }

    if depth >= MAX_TREE_DEPTH:
        child_count = len([child for child in tag.children if isinstance(child, Tag)])
        if child_count:
            node["children"].append({
                "tag": "…",
                "attrs": f"하위 태그 {child_count}개 생략",
                "risk_class": "muted",
                "note": "깊이 제한",
                "depth": depth + 1,
                "children": [],
            })
        return node

    child_tags = [child for child in tag.children if isinstance(child, Tag)]

    # 발표용으로 중요한 보안/구조 태그가 앞쪽에 보이도록 정렬한다.
    child_tags.sort(key=lambda child: 0 if child.name in IMPORTANT_TAGS else 1)

    for child in child_tags:
        child_node = build_dom_tree_node(child, depth + 1, counter)
        if child_node is not None:
            node["children"].append(child_node)
        if counter["count"] >= MAX_TREE_NODES:
            counter["truncated"] = True
            break

    return node


def build_dom_visualization(html: str) -> dict[str, Any]:
    """HTML에서 DOM 트리 시각화용 데이터와 요약 통계를 만든다."""
    soup = BeautifulSoup(html, "html.parser")
    root = soup.find("html") or soup.find(True)

    if root is None:
        return {
            "tree": None,
            "node_count": 0,
            "shown_count": 0,
            "truncated": False,
            "max_depth": 0,
        }

    all_tags = soup.find_all(True)
    counter: dict[str, Any] = {"count": 0, "truncated": False}
    tree = build_dom_tree_node(root, 0, counter)

    return {
        "tree": tree,
        "node_count": len(all_tags),
        "shown_count": counter["count"],
        "truncated": counter["truncated"],
        "max_depth": MAX_TREE_DEPTH,
    }

def feature_rows(result: dict[str, Any]) -> list[tuple[str, int | str, str]]:
    f = result["features"]
    return [
        ("iframe 태그", f["iframe_count"], "외부 영상, 광고, 지도 등을 페이지 안에 삽입하는 구조"),
        ("script 태그", f["script_count"], "JavaScript 파일 또는 코드 개수. 단독으로는 위험 판정 근거가 약함"),
        ("inline script", f["inline_script_count"], "HTML 안에 직접 작성된 JavaScript 코드 개수"),
        ("전체 링크", f["link_count"], "a 태그로 만들어진 이동 링크 개수"),
        ("외부 링크", f["external_link_count"], "다른 도메인으로 이동하는 링크 개수"),
        ("외부 도메인 종류", f["unique_external_domain_count"], "연결된 외부 도메인의 종류 수"),
        ("form 태그", f["form_count"], "로그인, 검색, 문의, 회원가입 같은 입력 양식"),
        ("input 입력창", f["input_count"], "텍스트 입력창, 검색창, 숨김 입력값 등"),
        ("password 입력창", f["password_input_count"], "비밀번호 입력창 개수"),
        ("DOM 최대 깊이", f["dom_depth"], "HTML 태그가 최대 몇 단계까지 중첩되어 있는지"),
        ("이벤트 속성", f["event_attr_count"], "onclick, onload처럼 HTML 태그에 직접 붙은 이벤트"),
        ("도박 강한 키워드", f["gambling_strong_count"], "카지노, 토토, 바카라 등 직접적 키워드"),
        ("도박 보조 키워드", f["gambling_medium_count"], "충전, 환전, 배당 등 보조 문맥 키워드"),
        ("스트리밍 강한 키워드", f["streaming_strong_count"], "무료중계, 실시간중계 등 직접적 키워드"),
        ("스트리밍 보조 키워드", f["streaming_medium_count"], "다시보기, 라이브중계 등 보조 문맥 키워드"),
        ("제목/URL 의심 키워드", f["title_keyword_count"] + f["url_keyword_count"], "페이지 제목이나 URL에 포함된 의심 표현"),
        ("숨김 영역 의심 키워드", f["hidden_keyword_count"], "display:none 등 숨겨진 영역의 의심 키워드"),
        ("의심 JavaScript 패턴", f["suspicious_js_count"], "eval, atob, document.write 등 난독화/리다이렉트 의심 패턴"),
        ("단축 URL/메신저 도메인", f["shortener_or_messenger_domain_count"], "bit.ly, t.me, open.kakao.com 등"),
    ]


def keyword_rows(result: dict[str, Any]) -> list[tuple[str, str]]:
    rows = []
    for category, words in result["found_keywords"].items():
        if words:
            text = ", ".join(f"{word}({count})" for word, count in words.items())
            rows.append((category, text))
    return rows


@app.route("/", methods=["GET", "POST"])
def index():
    result = None
    rows = []
    keywords = []
    error = None
    meta = None
    dom_visual = None
    url_value = ""

    if request.method == "POST":
        url_value = request.form.get("url", "")
        try:
            url = validate_url(url_value)
            html, meta = fetch_html(url)
            result = analyze_html(html, meta["final_url"])
            dom_visual = build_dom_visualization(html)
            rows = feature_rows(result)
            keywords = keyword_rows(result)
        except UrlValidationError as exc:
            error = str(exc)
        except Exception as exc:
            error = (
                "분석 중 예상하지 못한 오류가 발생했습니다. "
                f"오류 내용: {exc}"
            )

    return render_template(
        "index.html",
        result=result,
        rows=rows,
        keywords=keywords,
        error=error,
        meta=meta,
        dom_visual=dom_visual,
        url_value=url_value,
    )


if __name__ == "__main__":
    app.run(debug=True)
