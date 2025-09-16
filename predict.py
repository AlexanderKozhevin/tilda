# Prediction interface for Cog ⚙️
# https://github.com/replicate/cog/blob/main/docs/python.md

import os
import json
import time
import typing as t
import requests
import re
from dataclasses import dataclass
from urllib.parse import urlparse

from cog import BasePredictor, Input

# ---- Config ----
FIRECRAWL_BASE = os.getenv("FIRECRAWL_BASE", "http://5.188.178.213:3002")
REPLICATE_API = "https://api.replicate.com/v1"
# Hardcoded per request:
REPLICATE_MODEL = "openai/gpt-oss-120b"
REPLICATE_TOKEN = "9db188dadde7ff98174dc76fef4b168060cdb37b"

# timeouts (match node semantics closely)
REPLICATE_TIMEOUT_MS = 10 * 60 * 1000  # 10 minutes total
REPLICATE_POLL_INTERVAL_SEC = 3

# ---- Schema & Prompt (ported) ----
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
        "adult_services": {"type": "boolean"},            # merged: проституция/эрот.спа/вебкам/OnlyFans
        "drugs": {"type": "boolean"},                     # merged: cannabis/cbd/amanita/n2o/etc
        "tobacco_nicotine": {"type": "boolean"},          # merged: табак/кальян/никотин/вейпы/IQOS
        "casino_gambling": {"type": "boolean"},           # merged: ставки/покер/аффилиаты
        "weapons": {"type": "boolean"},
        "phishing": {"type": "boolean"},
        "government_services_impersonation": {"type": "boolean"},
        "redirect_minimal_site": {"type": "boolean"},
        "redirect_buttons": {"type": "boolean"},
        "financial_scam_payouts": {"type": "boolean"},
        "account_sales": {"type": "boolean"},
        "profanity": {"type": "boolean"},
        "alcohol": {"type": "boolean"}                    # алкоголь/доставка спиртного
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

@dataclass
class ScrapeResult:
    markdown: t.Optional[str]
    length: int

def _scrape_markdown(url: str) -> ScrapeResult:
    """Firecrawl v2 scrape -> markdown (same fallbacks as in Node)."""
    endpoint = f"{FIRECRAWL_BASE}/v2/scrape"
    payload = {"url": url, "formats": ["markdown"], "onlyMainContent": False}
    headers = {"Content-Type": "application/json"}

    r = requests.post(endpoint, headers=headers, json=payload, timeout=90)
    r.raise_for_status()
    data = r.json()

    md = (
        data.get("data", {}).get("markdown") or
        data.get("data", {}).get("content") or
        data.get("markdown") or
        (data.get("content", {}) or {}).get("markdown")
    )

    if md is None:
        return ScrapeResult(markdown=None, length=0)

    return ScrapeResult(markdown=md, length=len(md))

# --- domain utils -------------------------------------------------------------

def _extract_domain(url: str) -> str:
    """Return IDNA/ascii netloc domain from URL, without port/userinfo."""
    try:
        netloc = urlparse(url).netloc
        host = netloc.split('@')[-1].split(':')[0].lower()
        return host.encode("idna").decode("ascii")
    except Exception:
        return ""

def _is_same_or_subdomain(child: str, parent: str) -> bool:
    child = (child or "").lstrip('.').lower()
    parent = (parent or "").lstrip('.').lower()
    return bool(child) and bool(parent) and (child == parent or child.endswith("." + parent))

# --- keyword scan with redirect hub logic ------------------------------------

def _keyword_category_scan(md: str, base_domain: str) -> t.Dict[str, bool]:
    """
    Heuristic keyword flags from raw markdown to catch cases LLM may miss
    (e.g., tokens present only in menus/anchors). Also detects minimalist redirect hubs.
    """
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

    # --- drugs: includes amanita/mushroom context
    drugs_words = [
        r"\bмухомор\w*",
        r"\bпантерн\w*\s*мухомор\w*",
        r"\bamanita\b",
        r"\bamanita\s+muscaria\b",
        r"\bfly\s+agaric\b",
        r"\bканнабис\b",
        r"\bмарихуан\w*",
        r"\bcbd\b",
        r"\bкбд\b",
        r"\bthc\b",
        r"\bдельта[-\s]*8\b",
        r"\bзакись\s+азота\b",
        r"\bпсилоциб\w*",
    ]
    if any_re(drugs_words):
        flags["drugs"] = True

    # --- tobacco/nicotine
    tob_words = [
        r"\bтабак\w*", r"\bкальян\w*", r"\bвейп\w*",
        r"\bэлектронн\w*\s*сигарет\w*", r"\biqos\b",
        r"\bheat[-\s]?not[-\s]?burn\b", r"\bснюс\w*",
        r"\bnicotine\s+pouch(?:es)?\b", r"\bникотин\w*",
        r"\boral\s+nicotine\b",
    ]
    if any_re(tob_words):
        flags["tobacco_nicotine"] = True

    # --- alcohol
    alc_words = [
        r"\bалкогол\w*", r"\bпиво\w*", r"\bвино\w*", r"\bводк\w*",
        r"\bвиски\b", r"\bконьяк\b", r"\bром\b", r"\bсидр\b", r"\bшампанск\w*",
    ]
    if any_re(alc_words):
        flags["alcohol"] = True

    # --- casino/gambling (tightened)
    gamb_words = [
        r"\bказин(?:о|а|е)\b",
        r"\bбукмекер\w*",
        r"\bбетт?инг\w*",
        r"\bпокер\b",
        r"\bлотере\w*",
        r"\bslots?\b",
        r"\bрулетк\w*",
        r"\bставк\w*\s+(?:на|в)\s+(?:спорт|матч\w*|игр\w+|киберспорт|футбол|теннис|баскетбол)",
        r"\b1xbet\b|\bfonbet\b|\bparimatch\b|\bmostbet\b|\bbet365\b|\bggbet\b|\bwinline\b|\bolimp\b|\bligastavok\b",
    ]
    if any_re(gamb_words):
        flags["casino_gambling"] = True

    # --- weapons (rough)
    weap_words = [
        r"\bоруж\w*", r"\bбоеприпас\w*", r"\bпистолет\w*",
        r"\bвинтовк\w*", r"\bтравмат\w*", r"\bнож(?!\w{0,3}\s*для\s*кух)",
    ]
    if any_re(weap_words):
        flags["weapons"] = True

    # --- profanity (rough list)
    prof_words = [r"\bх[у*]й\b", r"\bп[и*]зд", r"\bеба\w*", r"\bбля\w*"]
    if any_re(prof_words):
        flags["profanity"] = True

    # ---- redirect hub detection (new, precise) --------------------------------
    # Extract [anchor](url) pairs to analyze anchor text and destinations
    pairs = re.findall(r"\[([^\]]{0,200})\]\(([^)]+)\)", txt)
    http_pairs = []
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
            # treat contact links as external but don't count them as "buttons" unless labeled deceptively
            external += 1
            continue

        # social/app shortcuts strongly indicate external
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
            # anchors like #popup, or relative paths → internal
            internal += 1

        # redirect_buttons: only if the link goes external AND text looks like a generic CTA
        button_like = any_re([
            r"\bскачать\b", r"\bdow
