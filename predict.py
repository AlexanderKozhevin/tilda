# Prediction interface for Cog ⚙️
# https://github.com/replicate/cog/blob/main/docs/python.md

import os
import json
import time
import typing as t
import requests
from dataclasses import dataclass

from cog import BasePredictor, Input

# ---- Config ----
FIRECRAWL_BASE = os.getenv("FIRECRAWL_BASE", "http://5.188.178.213:3002")
REPLICATE_API = "https://api.replicate.com/v1"
# Hardcoded per request:
REPLICATE_MODEL = "openai/gpt-oss-120b"
REPLICATE_TOKEN = "9db188dadde7ff98174dc76fef4b168060cdb37b"

# timeouts
REPLICATE_TIMEOUT_MS = 10 * 60 * 1000  # 10 minutes
REPLICATE_POLL_INTERVAL_SEC = 3

# ---- Schemas ----
SCHEMA_HARD = json.dumps({
  "type": "object",
  "properties": {
    "is_fraud": {"type": "boolean"},
    "risk_score": {"type": "number", "minimum": 0, "maximum": 1},
    "verdict": {"type": "string", "maxLength": 220},
    "content_categories": {
      "type": "object",
      "properties": {
        "porn_erotica": {"type": "boolean"},
        "sexual_services": {"type": "boolean"},
        "drugs": {"type": "boolean"},
        "extremism": {"type": "boolean"},
        "casino_gambling": {"type": "boolean"},
        "weapons": {"type": "boolean"},
        "phishing": {"type": "boolean"},
        "government_services_impersonation": {"type": "boolean"},
        "redirect_buttons": {"type": "boolean"},
        "financial_scam_payouts": {"type": "boolean"}
      },
      "required": [
        "porn_erotica","sexual_services","drugs","extremism","casino_gambling",
        "weapons","phishing","government_services_impersonation","redirect_buttons",
        "financial_scam_payouts"
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

SCHEMA_SOFT = json.dumps({
  "type": "object",
  "properties": {
    "soft_score": { "type": "number", "minimum": 0, "maximum": 1 },
    "soft_verdict": { "type": "string", "maxLength": 220 },
    "undesired_categories": {
      "type": "object",
      "properties": {
        "обманные_кнопки_перенаправления": { "type": "boolean" },
        "тонкий_лендинг_с_редиректом": { "type": "boolean" },
        "ненормативная_лексика": { "type": "boolean" },
        "onlyfans": { "type": "boolean" },
        "вебкам": { "type": "boolean" },
        "обнаженные_части_тела": { "type": "boolean" },
        "картинки_откровенного_характера": { "type": "boolean" },
        "эротические_шоу": { "type": "boolean" },
        "секс_по_видеозвонку": { "type": "boolean" },
        "отсутствует_возрастное_ограничение_на_откровенный_контент": { "type": "boolean" },
        "быстрый_заработок": { "type": "boolean" },
        "легкий_заработок": { "type": "boolean" },
        "доставка_алкогольной_продукции": { "type": "boolean" },
        "доставка_этилового_спирта": { "type": "boolean" },
        "доставка_никотинсодержащей_продукции": { "type": "boolean" },
        "доставка_табачной_продукции": { "type": "boolean" },
        "снюс": { "type": "boolean" },
        "доставка_одноразовых_электронных_сигарет": { "type": "boolean" },
        "IQOS": { "type": "boolean" },
        "табак_для_кальяна": { "type": "boolean" },
        "доставка_кальяна": { "type": "boolean" },
        "кальянный_кейтеринг": { "type": "boolean" },
        "прокат_кальяна": { "type": "boolean" },
        "доставка_алкоголя_круглосуточно_24_7": { "type": "boolean" }
      },
      "required": [
        "обманные_кнопки_перенаправления","тонкий_лендинг_с_редиректом",
        "ненормативная_лексика","onlyfans","вебкам","обнаженные_части_тела",
        "картинки_откровенного_характера","эротические_шоу","секс_по_видеозвонку",
        "отсутствует_возрастное_ограничение_на_откровенный_контент",
        "быстрый_заработок","легкий_заработок",
        "доставка_алкогольной_продукции","доставка_этилового_спирта",
        "доставка_никотинсодержащей_продукции","доставка_табачной_продукции",
        "снюс","доставка_одноразовых_электронных_сигарет","IQOS",
        "табак_для_кальяна","доставка_кальяна","кальянный_кейтеринг",
        "прокат_кальяна","доставка_алкоголя_круглосуточно_24_7"
      ],
      "additionalProperties": False
    },
    "evidence": {
      "type": "array",
      "items": { "type": "string", "maxLength": 120 },
      "minItems": 1, "maxItems": 6
    },
    "hosting": {
      "type": "object",
      "properties": {
        "domain": { "type": "string", "maxLength": 200 },
        "is_tilda": { "type": "boolean" }
      },
      "required": ["domain","is_tilda"],
      "additionalProperties": False
    }
  },
  "required": ["soft_score","soft_verdict","undesired_categories","evidence","hosting"],
  "additionalProperties": False
})

# ---- Prompts ----
PROMPT_HARD = f"""You are a web security & trust & safety analyst.

Rules (very strict):
1) Output ONLY valid **minified JSON** matching the provided schema. No prose, markdown, comments, or extra keys.
2) Use ONLY on-page content (the scraped markdown below). Do NOT imagine images. Treat alt-text, filenames, captions, anchors, and button labels as evidence. Do NOT follow links.
3) Detect the original page language (ISO 639-1, optional region). Write both "summary" and "keywords" in Russian language only!
4) Fill "hosting":
   - "domain": the primary domain you can infer from links/markdown context; if unknown, use an empty string "".
   - "is_tilda": true if the domain looks like a Tilda host (e.g., ends with ".tilda.ws" or similar Tilda patterns); else false.
5) Category definitions ("content_categories"): (omitted here for brevity, same as schema)
6) Fraud rubric: (same as before)
7) "verdict"/"evidence"/"impersonated_brands"/"keywords"/"summary": (same as before)
12) Be conservative.

Schema: {SCHEMA_HARD}

Return ONLY the JSON object.
"""

PROMPT_SOFT = f"""You are a web content risk annotator.

Rules (very strict):
1) Output ONLY valid **minified JSON** per schema. No prose/markdown/comments/extra keys.
2) Use ONLY on-page content (scraped markdown below). Do NOT follow links or imagine images. Alt-text/filenames/captions/anchors/buttons count as evidence.
3) Set "undesired_categories" strictly from explicit on-page mentions/promotions. If absent — false.
4) "тонкий_лендинг_с_редиректом": мало контента, 1–2 кнопки (часто в Telegram), основной смысл — увести пользователя.
5) "soft_score": 0..1 интенсивность/агрессивность нежелательных сигналов.
6) "soft_verdict": одна фраза (<=220 символов) о ключевых нежелательных темах.
7) "evidence": 1–6 коротких цитат/фрагментов (PII убрать).
8) "hosting": заполнить как в HARD.
9) Не классифицируйте тяжёлые нарушения — это зона HARD.

Schema: {SCHEMA_SOFT}

Return ONLY the JSON object.
"""

# ---- Utils ----
@dataclass
class ScrapeResult:
    markdown: t.Optional[str]
    length: int

def _scrape_markdown(url: str) -> ScrapeResult:
    endpoint = f"{FIRECRAWL_BASE}/v2/scrape"
    payload = {"url": url, "formats": ["markdown"]}
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
    max_chars = int(os.getenv("MAX_MARKDOWN_CHARS", "120000"))
    if len(md) > max_chars:
        md = md[:max_chars]
    return ScrapeResult(markdown=md, length=len(md))

def _replicate_create_prediction(prompt: str) -> str:
    url = f"{REPLICATE_API}/models/{REPLICATE_MODEL}/predictions"
    headers = {"Authorization": f"Bearer {REPLICATE_TOKEN}", "Content-Type": "application/json"}
    body = {"input": {"top_p": 1, "prompt": prompt, "max_tokens": 8024, "temperature": 0.1, "presence_penalty": 0, "frequency_penalty": 0}}
    resp = requests.post(url, headers=headers, json=body, timeout=60)
    if resp.status_code == 404:
        url = f"{REPLICATE_API}/predictions"
        body = {"version": REPLICATE_MODEL, "input": body["input"]}
        resp = requests.post(url, headers=headers, json=body, timeout=60)
    resp.raise_for_status()
    data = resp.json()
    prediction_id = data.get("id")
    if not prediction_id:
        raise RuntimeError("No prediction ID from Replicate API")
    return prediction_id

def _replicate_poll_prediction(prediction_id: str) -> t.Any:
    headers = {"Authorization": f"Bearer {REPLICATE_TOKEN}", "Content-Type": "application/json"}
    start = time.time()
    timeout_sec = REPLICATE_TIMEOUT_MS / 1000.0
    while (time.time() - start) < timeout_sec:
        url = f"{REPLICATE_API}/predictions/{prediction_id}"
        r = requests.get(url, headers=headers, timeout=30)
        r.raise_for_status()
        data = r.json()
        status = data.get("status")
        if status == "succeeded":
            output = data.get("output")
            if isinstance(output, list):
                output = "".join([s for s in output if isinstance(s, str) and s.strip()])
            if isinstance(output, str):
                try:
                    return json.loads(output)
                except Exception as e:
                    raise RuntimeError(f"Invalid JSON in Replicate output: {e}") from e
            elif isinstance(output, dict):
                return output
            else:
                raise RuntimeError("Unexpected Replicate output type")
        elif status in ("failed", "canceled"):
            err = data.get("error") or "Unknown error"
            raise RuntimeError(f"Replicate prediction {status}: {err}")
        time.sleep(REPLICATE_POLL_INTERVAL_SEC)
    raise TimeoutError("Timeout waiting for Replicate prediction to complete")

# ---- Orchestration ----
HEAVY_HARD_FLAGS = {
    "drugs","extremism","weapons","casino_gambling","sexual_services",
    "phishing","financial_scam_payouts","government_services_impersonation"
}
HARD_BLOCK_SCORE = float(os.getenv("HARD_BLOCK_SCORE", "0.70"))

def _build_prompt_hard(md: str) -> str:
    return f"{PROMPT_HARD}\n\nPage markdown:\n\n{md}"

def _build_prompt_soft(md: str) -> str:
    return f"{PROMPT_SOFT}\n\nPage markdown:\n\n{md}"

def _is_hard_block(result: dict) -> bool:
    try:
        if result.get("is_fraud"):
            return True
        if (result.get("risk_score") or 0) >= HARD_BLOCK_SCORE:
            return True
        cc = result.get("content_categories") or {}
        if any(bool(cc.get(k)) for k in HEAVY_HARD_FLAGS):
            return True
        return False
    except Exception:
        return True

def _mk_response(*, stage: str, url: str, hard: t.Optional[dict]=None, soft: t.Optional[dict]=None,
                 success: bool=True, error: t.Optional[str]=None) -> dict:
    """Unified response with top-level 'fraud' and 'probability' from HARD stage."""
    fraud = None
    probability = None
    try:
        if isinstance(hard, dict):
            fraud = bool(hard.get("is_fraud", False))
            rs = hard.get("risk_score", None)
            probability = float(rs) if rs is not None else None
    except Exception:
        pass
    resp = {"success": success, "url": url, "stage": stage, "fraud": fraud, "probability": probability}
    if error is not None:
        resp["error"] = error
    if hard is not None:
        resp["hard"] = hard
    if soft is not None:
        resp["soft"] = soft
    return resp

class Predictor(BasePredictor):
    def setup(self) -> None:
        pass

    def predict(
        self,
        url: str = Input(description="Public URL to classify (HTML page to be scraped via Firecrawl)"),
    ) -> t.Dict[str, t.Any]:
        """
        Always two-step pipeline:
          1) HARD: block-worthy violations.
          2) If HARD passes, run SOFT and add soft flags.

        Returns:
          HARD blocks -> {"success":True,"url":...,"stage":"hard_block","fraud":bool,"probability":float,"hard":{...}}
          HARD passes -> {"success":True,"url":...,"stage":"soft_flags","fraud":bool,"probability":float,"hard":{...},"soft":{...}}
        """
        try:
            scraped = _scrape_markdown(url)
            print(scraped)
            if not scraped.markdown:
                return _mk_response(stage="hard", url=url, success=False, error="No markdown from Firecrawl")

            md = scraped.markdown

            # Step 1: HARD
            pid_hard = _replicate_create_prediction(_build_prompt_hard(md))
            hard = _replicate_poll_prediction(pid_hard)
            try:
                print(f"[HARD] is_fraud={hard.get('is_fraud')} risk={hard.get('risk_score')} lang={hard.get('language')}")
            except Exception:
                pass

            if _is_hard_block(hard):
                return _mk_response(stage="hard_block", url=url, hard=hard)

            # Step 2: SOFT
            pid_soft = _replicate_create_prediction(_build_prompt_soft(md))
            soft = _replicate_poll_prediction(pid_soft)
            return _mk_response(stage="soft_flags", url=url, hard=hard, soft=soft)

        except Exception as e:
            return _mk_response(stage="error", url=url, success=False, error=str(e))
