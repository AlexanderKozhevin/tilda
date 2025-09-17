# Prediction interface for Cog ⚙️
# https://github.com/replicate/cog/blob/main/docs/python.md

import os
import json
import time
import typing as t
import requests
import re
import traceback
from dataclasses import dataclass
from urllib.parse import urlparse

from cog import BasePredictor, Input

# ==== Config =================================================================
FIRECRAWL_BASE = os.getenv("FIRECRAWL_BASE", "http://5.188.178.213:3002")
REPLICATE_API = "https://api.replicate.com/v1"
# Hardcoded per request:
REPLICATE_MODEL = "openai/gpt-oss-120b"
REPLICATE_TOKEN = "9db188dadde7ff98174dc76fef4b168060cdb37b"

# timeouts (match node semantics closely)
REPLICATE_TIMEOUT_MS = 10 * 60 * 1000  # 10 minutes total
REPLICATE_POLL_INTERVAL_SEC = 3

# Logging controls
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()      # "DEBUG" | "INFO" | "WARN" | "ERROR"
LOG_SAMPLE_CHARS = int(os.getenv("LOG_SAMPLE_CHARS", "1200"))  # how many chars to print from big blobs
LOG_JSON_PREVIEW_KEYS = int(os.getenv("LOG_JSON_PREVIEW_KEYS", "30"))  # how many keys in dicts to preview
LOG_MAX_EVIDENCE = int(os.getenv("LOG_MAX_EVIDENCE", "6"))

# ==== Lightweight structured logging =========================================
def _now() -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())

def _lvl_ok(min_level: str) -> bool:
    order = {"DEBUG": 10, "INFO": 20, "WARN": 30, "ERROR": 40}
    return order.get(LOG_LEVEL, 20) <= order.get(min_level, 20)

def log(level: str, msg: str, **kv: t.Any) -> None:
    if not _lvl_ok(level):
        return
    try:
        payload = {"ts": _now(), "level": level, "msg": msg}
        if kv:
            # keep payload small
            safe = {}
            for k, v in kv.items():
                if isinstance(v, str) and len(v) > LOG_SAMPLE_CHARS:
                    safe[k] = v[:LOG_SAMPLE_CHARS] + f"... [len={len(v)}]"
                elif isinstance(v, (list, tuple)) and len(v) > LOG_JSON_PREVIEW_KEYS:
                    safe[k] = list(v[:LOG_JSON_PREVIEW_KEYS]) + [f"...(+{len(v)-LOG_JSON_PREVIEW_KEYS} more)"]
                elif isinstance(v, dict) and len(v) > LOG_JSON_PREVIEW_KEYS:
                    items = list(v.items())[:LOG_JSON_PREVIEW_KEYS]
                    safe[k] = dict(items)
                    safe[k]["__truncated__"] = f"+{len(v)-LOG_JSON_PREVIEW_KEYS} more keys"
                else:
                    safe[k] = v
            payload["kv"] = safe
        print(json.dumps(payload, ensure_ascii=False))
    except Exception:
        # Never let logging crash the pipeline
        try:
            print(f"[{_now()}] {level} {msg} (logging failed)")
        except Exception:
            pass

def log_debug(msg: str, **kv): log("DEBUG", msg, **kv)
def log_info(msg: str, **kv):  log("INFO", msg, **kv)
def log_warn(msg: str, **kv):  log("WARN", msg, **kv)
def log_error(msg: str, **kv): log("ERROR", msg, **kv)

# ---- Schema & Prompt (ported) -----------------------------------------------
SCHEMA = json.dumps({
  "type": "object",
  "properties": {
    "is_fraud": {"type": "boolean"},
    "risk_score": {"type": "number", "minimum": 0, "maximum": 1},
    "verdict": {"type": "string", "maxLength": 220},
    "content_categories": {
      "type": "object",
      "properties": {
        "porn_erotica": {"type": "boolean"},
        "adult_services": {"type": "boolean"},
        "drugs": {"type": "boolean"},
        "tobacco_nicotine": {"type": "boolean"},
        "casino_gambling": {"type": "boolean"},
        "weapons": {"type": "boolean"},
        "phishing": {"type": "boolean"},
        "government_services_impersonation": {"type": "boolean"},
        "redirect_minimal_site": {"type": "boolean"},
        "redirect_buttons": {"type": "boolean"},
        "financial_scam_payouts": {"type": "boolean"},
        "account_sales": {"type": "boolean"},
        "profanity": {"type": "boolean"},
        "alcohol": {"type": "boolean"}
      },
      "required": [
        "porn_erotica","adult_services","drugs","tobacco_nicotine","casino_gambling",
        "weapons","phishing","government_services_impersonation","redirect_minimal_site",
        "redirect_buttons","financial_scam_payouts","account_sales","profanity","alcohol"
      ],
      "additionalProperties": False
    },
    "language": {"type": "string", "pattern": "^[a-z]{2}(-[A-Z]{2})?$"},
    "summary": {"type": "string", "maxLength": 400},
    "keywords": {
      "type": "array",
      "items": {"type": "string", "maxLength": 40},
      "minItems": 3,
      "maxItems": 12
    },
    "evidence": {
      "type": "array",
      "items": {"type": "string", "maxLength": 120},
      "minItems": 1,
      "maxItems": 6
    },
    "impersonated_brands": {
      "type": "array",
      "items": {"type": "string", "maxLength": 50},
      "minItems": 0,
      "maxItems": 8
    },
    "hosting": {
      "type": "object",
      "properties": {
        "domain": {"type": "string", "maxLength": 200},
        "is_tilda": {"type": "boolean"}
      },
      "required": ["domain", "is_tilda"],
      "additionalProperties": False
    }
  },
  "required": [
    "is_fraud","risk_score","verdict",
    "content_categories","language","summary","keywords",
    "evidence","impersonated_brands","hosting"
  ],
  "additionalProperties": False
})

PROMPT_HEADER = f"""You are a web security & trust & safety analyst.

Rules (very strict):
1) Output ONLY valid **minified JSON** matching the provided schema. No prose, markdown, comments, or extra keys.
2) Use ONLY on-page content (the scraped markdown below). Do NOT imagine images. Treat alt-text, filenames, captions, anchors, and button labels as text evidence. Do NOT follow links.
2a) Меню, названия разделов и кнопок, хлебные крошки и анкоры считать полноправной уликой. Если встречаются "мухомор", "Amanita muscaria", "fly agaric", "пантерный мухомор" — это сигналы категории drugs=true.
3) Detect the original page language (ISO 639-1, optional region). Write both "summary" and "keywords" in Russian language only!
4) Fill "hosting":
   - "domain": the primary domain you can infer from links/markdown context; if unknown, use an empty string "".
   - "is_tilda": true if the domain looks like a Tilda host (e.g., ends with ".tilda.ws" or similar Tilda patterns); else false.

5) Category definitions ("content_categories"):
   - porn_erotica: порнография/откровенный контент (включая откровенную наготу и отсутствие age-gate).
   - adult_services: проституция/эскорт/эротический массаж/шибари/вебкам/OnlyFans/«секс по видеосвязи».
   - drugs: нелегальные/контролируемые вещества и промо/продажи (включая каннабис/КБД, мухоморы, закись азота и т.п.).
   - tobacco_nicotine: табак/кальян/жевательный табак/снюс-подобные/oral nicotine, одноразки/вейпы, IQOS/heat-not-burn.
   - casino_gambling: казино/букмекеры/ставки/покер/лотереи, включая аффилиатные лендинги.
   - weapons: оружие/боеприпасы/боевые ножи/инструкции по обороту.
   - phishing: кража учётных данных/платежей/seed/wallet drains, фальшивые формы/логины.
   - government_services_impersonation: имитация госпорталов/сервисов для сбора данных/платежей.
   - redirect_minimal_site: минималистичный «хаб-редирект» (очень мало текста, 1–5 кнопок на внешние сайты; часто *.tilda.ws).
   - redirect_buttons: обманные кнопки ("Скачать/Продолжить/Play") ведущие вовне.
   - financial_scam_payouts: «мгновенные выплаты/выгоды» за взнос; пирамиды.
   - account_sales: продажа аккаунтов (соцсети/сервисы/игры и т.п.).
   - profanity: ненормативная лексика.
   - alcohol: алкоголь/доставка спиртного.

6) Heuristics & exceptions:
   - Наличие adult/drugs/tobacco_nicotine/profanity/alcohol отмечай в категориях. Это может быть нежелательный контент, но сам по себе не равен мошенничеству.
   - «Хаб-редирект»: если страница крайне короткая и почти целиком из кнопок/якорей на сторонние сайты — ставь redirect_minimal_site=true; если формулировки кнопок обманные — также redirect_buttons=true.
   - government/brand impersonation → phishing или government_services_impersonation.

7) Fraud rubric:
   - "is_fraud": оставь как поле; будет выставлено системой после объединения сигналов. Модель может давать свою оценку, но финальное значение задаст пост-обработка.
   - "risk_score":
       ≥0.90 явное мошенничество/phishing/имперсонация с формами ввода, seed/wallet и пр.
       0.70–0.89 сильные признаки нарушений (прямые продажи наркотиков, явные услуги проституции, экстремизм, торговля оружием, казино с платежными воронками, обманные редирект-хабы).
       0.40–0.69 частичные/косвенные признаки, намёки, слабые сигналы.
       <0.40 скорее информационный или легальный контент.

8) "verdict": одно короткое предложение (<=220 chars), объясняющее основную причину оценки, упоминая категории (и бренды/гос.названия при имперсонации).
9) "evidence": 1–6 коротких цитат из markdown, подтверждающих решение (убирай PII, оставляй только релевантное).
10) "impersonated_brands": бренды/организации, которых имитируют (банки, кошельки, гос.сервисы); иначе [].
11) "keywords": 3–12 тематических ключевых слов (без хэштегов), на языке страницы, без дубликатов.
12) "summary": <=400 символов, на языке страницы, нейтральным тоном.
13) Будь консервативен: если сигналы слабые — занижай score и оставляй не относящиеся категории false.

Schema: {SCHEMA}

Return ONLY the JSON object.
"""

# ==== Types ==================================================================
@dataclass
class ScrapeResult:
    markdown: t.Optional[str]
    length: int
    duration_ms: int

# ==== Firecrawl scrape ========================================================
def _scrape_markdown(url: str) -> ScrapeResult:
    """Firecrawl v2 scrape -> markdown (same fallbacks as in Node)."""
    endpoint = f"{FIRECRAWL_BASE}/v2/scrape"
    payload = {"url": url, "formats": ["markdown"], "onlyMainContent": False}
    headers = {"Content-Type": "application/json"}

    t0 = time.time()
    log_info("firecrawl.request.start", endpoint=endpoint, payload=payload)
    try:
        r = requests.post(endpoint, headers=headers, json=payload, timeout=90)
        status = r.status_code
        dur = int((time.time() - t0) * 1000)
        log_info("firecrawl.request.done", status=status, duration_ms=dur)
        r.raise_for_status()
        data = r.json()
        # Keep response size logging safe
        try:
            raw_len = len(r.text or "")
        except Exception:
            raw_len = -1
        log_debug("firecrawl.response.parsed", raw_length=raw_len, keys=list(data.keys()) if isinstance(data, dict) else None)

        md = (
            data.get("data", {}).get("markdown") or
            data.get("data", {}).get("content") or
            data.get("markdown") or
            (data.get("content", {}) or {}).get("markdown")
        )
        md_len = len(md) if isinstance(md, str) else 0
        log_info("firecrawl.markdown.extracted", markdown_len=md_len, sample=(md[:LOG_SAMPLE_CHARS] if md else ""))

        return ScrapeResult(markdown=md, length=md_len, duration_ms=dur)
    except Exception as e:
        dur = int((time.time() - t0) * 1000)
        log_error("firecrawl.request.error", duration_ms=dur, error=str(e), tb=traceback.format_exc()[:2000])
        return ScrapeResult(markdown=None, length=0, duration_ms=dur)

# --- domain utils -------------------------------------------------------------
def _extract_domain(url: str) -> str:
    """Return IDNA/ascii netloc domain from URL, without port/userinfo."""
    try:
        netloc = urlparse(url).netloc
        host = netloc.split('@')[-1].split(':')[0].lower()
        dom = host.encode("idna").decode("ascii")
        log_debug("url.domain.extracted", url=url, domain=dom)
        return dom
    except Exception as e:
        log_warn("url.domain.extract.fail", url=url, error=str(e))
        return ""

def _is_same_or_subdomain(child: str, parent: str) -> bool:
    child = (child or "").lstrip('.').lower()
    parent = (parent or "").lstrip('.').lower()
    same = bool(child) and bool(parent) and (child == parent or child.endswith("." + parent))
    log_debug("url.domain.compare", child=child, parent=parent, match=same)
    return same

# --- keyword scan with redirect hub logic ------------------------------------
def _keyword_category_scan(md: str, base_domain: str) -> t.Dict[str, bool]:
    """
    Heuristic keyword flags from raw markdown to catch cases LLM may miss.
    Also detects minimalist redirect hubs.
    """
    t0 = time.time()
    txt = (md or "")
    lower = txt.lower()

    def any_re(patterns: t.List[str], hay: str = lower) -> bool:
        return any(re.search(p, hay, flags=re.IGNORECASE) for p in patterns)

    flags = {
        "porn_erotica": False,
        "adult_services": False,
        "drugs": False,
        "tobacco_nicotine": False,
        "casino_gambling": False,
        "weapons": False,
        "phishing": False,
        "government_services_impersonation": False,
        "redirect_minimal_site": False,
        "redirect_buttons": False,
        "financial_scam_payouts": False,
        "account_sales": False,
        "profanity": False,
        "alcohol": False,
    }

    # --- drugs
    drugs_words = [
        r"\bмухомор\w*", r"\bпантерн\w*\s*мухомор\w*", r"\bamanita\b", r"\bamanita\s+muscaria\b",
        r"\bfly\s+agaric\b", r"\bканнабис\b", r"\bмарихуан\w*", r"\bcbd\b", r"\bкбд\b", r"\bthc\b",
        r"\bдельта[-\s]*8\b", r"\bзакись\s+азота\b", r"\bпсилоциб\w*",
    ]
    if any_re(drugs_words):
        flags["drugs"] = True

    # --- tobacco/nicotine
    tob_words = [
        r"\bтабак\w*", r"\bкальян\w*", r"\bвейп\w*", r"\bэлектронн\w*\s*сигарет\w*", r"\biqos\b",
        r"\bheat[-\s]?not[-\s]?burn\b", r"\bснюс\w*", r"\bnicotine\s+pouch(?:es)?\b", r"\bникотин\w*", r"\boral\s+nicotine\b",
    ]
    if any_re(tob_words):
        flags["tobacco_nicotine"] = True

    # --- alcohol
    alc_words = [r"\bалкогол\w*", r"\bпиво\w*", r"\bвино\w*", r"\bводк\w*", r"\bвиски\b", r"\bконьяк\b", r"\bром\b", r"\bсидр\b", r"\bшампанск\w*"]
    if any_re(alc_words):
        flags["alcohol"] = True

    # --- casino/gambling
    gamb_words = [
        r"\bказин(?:о|а|е)\b", r"\bбукмекер\w*", r"\bбетт?инг\w*", r"\bпокер\b", r"\bлотере\w*", r"\bslots?\b",
        r"\bрулетк\w*", r"\bставк\w*\s+(?:на|в)\s+(?:спорт|матч\w*|игр\w+|киберспорт|футбол|теннис|баскетбол)",
        r"\b1xbet\b|\bfonbet\b|\bparimatch\b|\bmostbet\b|\bbet365\b|\bggbet\b|\bwinline\b|\bolimp\b|\bligastavok\b",
    ]
    if any_re(gamb_words):
        flags["casino_gambling"] = True

    # --- weapons
    weap_words = [r"\bоруж\w*", r"\bбоеприпас\w*", r"\bпистолет\w*", r"\bвинтовк\w*", r"\bтравмат\w*", r"\bнож(?!\w{0,3}\s*для\s*кух)"]
    if any_re(weap_words):
        flags["weapons"] = True

    # --- profanity
    prof_words = [r"\bх[у*]й\b", r"\bп[и*]зд", r"\bеба\w*", r"\bбля\w*"]
    if any_re(prof_words):
        flags["profanity"] = True

    # ---- redirect hub detection ---------------------------------------------
    pairs = re.findall(r"\[([^\]]{0,200})\]\(([^)]+)\)", txt)
    http_pairs: t.List[t.Tuple[str, str]] = []
    external = 0
    internal = 0
    base = (base_domain or "").lower()

    def _url_domain(u: str) -> str:
        try:
            if u.startswith("http"):
                dom = urlparse(u).netloc.split('@')[-1].split(':')[0].lower()
                return dom.encode("idna").decode("ascii")
            return ""
        except Exception:
            return ""

    # classify links
    for label, href in pairs:
        href_l = href.strip().lower()
        if href_l.startswith(("tel:", "mailto:")):
            external += 1
            continue

        if any(s in href_l for s in ("wa.me/", "t.me/", "telegram.me/", "telegram.org/", "vk.com/", "ok.ru/",
                                     "instagram.com/", "facebook.com/", "youtube.com/", "youtu.be/", "whatsapp.com/")):
            external += 1
        elif href_l.startswith("http"):
            dom = _url_domain(href_l)
            if dom and base and not _is_same_or_subdomain(dom, base):
                external += 1
            else:
                internal += 1
        else:
            internal += 1

        button_like = any(
            re.search(p, (label or "").lower()) for p in [
                r"\bскачать\b", r"\bdownload\b", r"\bplay\b", r"\bstart\b", r"\bcontinue\b", r"\bпродолжить\b",
                r"\bперейти\b", r"\bgo\b", r"\bclaim\b", r"\bget\b", r"\bполучить\b", r"\bjoin\b",
                r"\bsign\s*in\b", r"\bвойти\b", r"\blogin\b", r"\bлогин\b", r"\bрегист\w+", r"\binstall\b",
                r"\bopen\s+app\b", r"\bbonus\b", r"\bfree\b"
            ]
        )
        goes_external = (
            (not href_l) or
            href_l.startswith(("tel:", "mailto:")) or
            any(s in href_l for s in ("wa.me/", "t.me/", "telegram", "vk.com/", "ok.ru/",
                                      "instagram.com/", "facebook.com/", "youtube.com/", "youtu.be/",
                                      "whatsapp.com/")) or
            (href_l.startswith("http") and _url_domain(href_l) and base and not _is_same_or_subdomain(_url_domain(href_l), base))
        )
        if button_like and goes_external:
            flags["redirect_buttons"] = True

    words = len(re.findall(r"[A-Za-zА-Яа-я0-9]{3,}", lower))
    total_links = external + internal
    ext_share = (external / total_links) if total_links > 0 else 0.0

    if words <= 220 and 1 <= external <= 6 and ext_share >= 0.7:
        flags["redirect_minimal_site"] = True

    dur = int((time.time() - t0) * 1000)
    log_info(
        "keyword.scan.done",
        duration_ms=dur,
        words=words,
        links_total=total_links,
        links_external=external,
        links_internal=internal,
        ext_share=round(ext_share, 3),
        flags=flags
    )
    return flags

def _force_fraud_if_any_category_true(result: t.Dict[str, t.Any]) -> t.Dict[str, t.Any]:
    """If ANY boolean in content_categories == True -> enforce is_fraud = True."""
    try:
        cc = result.get("content_categories", {}) or {}
        any_true = any(bool(v) for v in cc.values())
        if any_true:
            result["is_fraud"] = True
        log_info("fraud.force.apply", any_category_true=any_true, final_is_fraud=result.get("is_fraud"))
        return result
    except Exception as e:
        log_warn("fraud.force.error", error=str(e))
        return result

# ==== Replicate API calls =====================================================
def _replicate_create_prediction(prompt: str) -> str:
    """Create prediction on Replicate; return prediction id."""
    url = f"{REPLICATE_API}/models/{REPLICATE_MODEL}/predictions"
    headers = {"Authorization": f"Bearer {REPLICATE_TOKEN}", "Content-Type": "application/json"}
    body = {
        "input": {
            "top_p": 1,
            "prompt": prompt,
            "max_tokens": 16000,
            "temperature": 0.1,
            "presence_penalty": 0,
            "frequency_penalty": 0,
        }
    }

    t0 = time.time()
    log_info("replicate.create.start", url=url, model=REPLICATE_MODEL)
    resp = requests.post(url, headers=headers, json=body, timeout=60)

    if resp.status_code == 404:
        url_fallback = f"{REPLICATE_API}/predictions"
        body_fb = {"version": REPLICATE_MODEL, "input": body["input"]}
        log_warn("replicate.create.fallback", to=url_fallback)
        resp = requests.post(url_fallback, headers=headers, json=body_fb, timeout=60)

    dur = int((time.time() - t0) * 1000)
    log_info("replicate.create.done", status=resp.status_code, duration_ms=dur)
    resp.raise_for_status()
    data = resp.json()
    prediction_id = data.get("id")
    log_info("replicate.create.id", id=prediction_id)
    if not prediction_id:
        raise RuntimeError("No prediction ID from Replicate API")
    return prediction_id

def _replicate_poll_prediction(prediction_id: str) -> t.Any:
    """Poll until succeeded/failed or timeout; return parsed JSON output."""
    headers = {"Authorization": f"Bearer {REPLICATE_TOKEN}", "Content-Type": "application/json"}
    start = time.time()
    timeout_sec = REPLICATE_TIMEOUT_MS / 1000.0
    polls = 0

    while (time.time() - start) < timeout_sec:
        polls += 1
        url = f"{REPLICATE_API}/predictions/{prediction_id}"
        t0 = time.time()
        try:
            r = requests.get(url, headers=headers, timeout=30)
            dur = int((time.time() - t0) * 1000)
            status = None
            try:
                data = r.json()
                status = data.get("status")
            except Exception:
                data = {}
            log_info("replicate.poll.tick", polls=polls, http_status=r.status_code, model_status=status, duration_ms=dur)
            r.raise_for_status()

            if status == "succeeded":
                output = data.get("output")
                # Normalize output (list of strings -> joined string)
                if isinstance(output, list):
                    joined = "".join([s for s in output if isinstance(s, str) and s.strip()])
                    log_debug("replicate.output.joined", length=len(joined))
                    output = joined
                # Parse JSON
                if isinstance(output, str):
                    try:
                        parsed = json.loads(output)
                        log_info("replicate.output.parsed.string", keys=list(parsed.keys()) if isinstance(parsed, dict) else None)
                        return parsed
                    except Exception as e:
                        sample = output[:LOG_SAMPLE_CHARS] if isinstance(output, str) else ""
                        log_error("replicate.output.json.error", error=str(e), sample=sample)
                        raise RuntimeError(f"Invalid JSON in Replicate output: {e}") from e
                elif isinstance(output, dict):
                    log_info("replicate.output.parsed.dict", keys=list(output.keys()))
                    return output
                else:
                    log_error("replicate.output.type.unexpected", type=str(type(output)))
                    raise RuntimeError("Unexpected Replicate output type")
            elif status in ("failed", "canceled"):
                err = data.get("error") or "Unknown error"
                log_error("replicate.poll.terminal", status=status, error=err)
                raise RuntimeError(f"Replicate prediction {status}: {err}")
        except Exception as e:
            log_warn("replicate.poll.error", error=str(e), tb=traceback.format_exc()[:1500])
        time.sleep(REPLICATE_POLL_INTERVAL_SEC)

    log_error("replicate.poll.timeout", prediction_id=prediction_id, timeout_sec=timeout_sec, polls=polls)
    raise TimeoutError("Timeout waiting for Replicate prediction to complete")

# ==== Predictor ===============================================================
class Predictor(BasePredictor):
    def setup(self) -> None:
        log_info("predictor.setup.ready", firecrawl_base=FIRECRAWL_BASE, model=REPLICATE_MODEL, timeout_ms=REPLICATE_TIMEOUT_MS)

    def predict(
        self,
        url: str = Input(description="Public URL to classify (HTML page to be scraped via Firecrawl)"),
    ) -> t.Dict[str, t.Any]:
        """
        Firecrawl -> markdown, Replicate classify (create + poll), parse JSON, return.

        Returns:
          {
            "success": true/false,
            "url": "<url>",
            "result": <json object>  # on success
            "error": "<message>"     # on failure
          }
        """
        log_info("predict.start", url=url)
        try:
            # 1) Scrape
            scraped = _scrape_markdown(url)
            log_info(
                "scrape.summary",
                ok=bool(scraped.markdown),
                markdown_len=scraped.length,
                duration_ms=scraped.duration_ms
            )
            if not scraped.markdown:
                return {"success": False, "url": url, "error": "No markdown from Firecrawl"}

            # 2) Domain / heuristics
            base_domain = _extract_domain(url)
            hints = _keyword_category_scan(scraped.markdown, base_domain)
            hint_tokens = [k for k, v in hints.items() if v]
            log_info("hints.ready", tokens=hint_tokens)

            # 3) Build prompt
            prompt = (
                f"{PROMPT_HEADER}\n\n"
                f"Signals (pre-detected category flags): {json.dumps(hint_tokens, ensure_ascii=False)}\n\n"
                f"Page markdown:\n\n{scraped.markdown}"
            )
            log_debug("prompt.built", length=len(prompt), sample=prompt[:LOG_SAMPLE_CHARS])

            # 4) Replicate: create + poll
            prediction_id = _replicate_create_prediction(prompt)
            log_info("replicate.prediction.created", id=prediction_id)

            parsed_json = _replicate_poll_prediction(prediction_id)
            if not isinstance(parsed_json, dict):
                log_error("replicate.result.type.invalid", got_type=str(type(parsed_json)))
                return {"success": False, "url": url, "error": "Replicate returned non-dict JSON"}

            # 5) Merge keyword flags (OR) and enforce is_fraud
            try:
                cc = parsed_json.get("content_categories") or {}
                # Ensure all keys exist and OR with hints
                for key in [
                    "porn_erotica","adult_services","drugs","tobacco_nicotine","casino_gambling",
                    "weapons","phishing","government_services_impersonation","redirect_minimal_site",
                    "redirect_buttons","financial_scam_payouts","account_sales","profanity","alcohol"
                ]:
                    cc[key] = bool(cc.get(key, False) or hints.get(key, False))
                parsed_json["content_categories"] = cc
                log_info("categories.merged", categories=cc)
            except Exception as e:
                log_warn("categories.merge.error", error=str(e))

            parsed_json = _force_fraud_if_any_category_true(parsed_json)

            # 6) Post-process logging: size, important fields
            try:
                ev = parsed_json.get("evidence") or []
                ev = ev[:LOG_MAX_EVIDENCE]
                log_info(
                    "result.summary",
                    is_fraud=parsed_json.get("is_fraud"),
                    risk_score=parsed_json.get("risk_score"),
                    language=parsed_json.get("language"),
                    verdict=(parsed_json.get("verdict") or "")[:220],
                    evidence=ev,
                    hosting=parsed_json.get("hosting"),
                )
            except Exception as e:
                log_warn("result.summary.error", error=str(e))

            return {"success": True, "url": url, "result": parsed_json}

        except Exception as e:
            log_error("predict.error", error=str(e), tb=traceback.format_exc()[:3000])
            return {"success": False, "url": url, "error": str(e)}
