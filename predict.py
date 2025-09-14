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

PROMPT_HEADER = f"""You are a web security & trust & safety analyst.

Rules (very strict):
1) Output ONLY valid **minified JSON** matching the provided schema. No prose, markdown, comments, or extra keys.
2) Use ONLY on-page content (the scraped markdown below). Do NOT imagine images. Treat alt-text, filenames, captions, anchors, and button labels as text evidence. Do NOT follow links.
3) Detect the original page language (ISO 639-1, optional region). Write both "summary" and "keywords" in Russian language only!
4) Fill "hosting":
   - "domain": the primary domain you can infer from links/markdown context; if unknown, use an empty string "".
   - "is_tilda": true if the domain looks like a Tilda host (e.g., ends with ".tilda.ws" or similar Tilda patterns); else false.
5) Category definitions ("content_categories"):
   - porn_erotica: porn/erotica/nudity meant for arousal (not the same as prostitution ads).
   - sexual_services: prostitution/paid sexual services/escorts/sex work ads.
   - drugs: illegal/controlled recreational drugs (incl. mushrooms) or paraphernalia sales/promo.
   - extremism: extremist symbols, propaganda, recruiting, praise of violent orgs/acts.
   - casino_gambling: casinos, betting, lotteries with real-money stakes or promos (incl. recognizable betting/casino logos).
   - weapons: sale/promo of firearms, ammunition, combat knives, or instructions to traffic these.
   - phishing: credential/payment capture, fake logins/2FA, seed phrases, wallet drains, brand or government impersonation forms.
   - government_services_impersonation: pages imitating official government portals/services to collect data or payments.
   - redirect_buttons: UI that disguises redirects (e.g., deceptive "Download/Play/Continue" that lead elsewhere).
   - financial_scam_payouts: promises of instant payouts/benefits with upfront fees, "get rich quick", pyramid-like pitches.
   Set each boolean strictly from the markdown evidence (true if present/promoted; otherwise false).
6) Fraud rubric:
   - "is_fraud": true if the page aims to deceive or steal (e.g., phishing, impersonation, payout scams). False otherwise.
   - "risk_score":
       ≥0.90 clear fraud/phishing/impersonation with capture forms, seed/wallet requests, or multiple severe violations.
       0.70–0.89 strong evidence of violations (e.g., explicit drug sales, prostitution ads, extremist propaganda, weapons trade, casino with payment funnels), or multiple red flags.
       0.40–0.69 partial/indirect evidence, suggestive language, or weak signals.
       <0.40 likely informational or benign.
7) "verdict": one concise sentence (<=220 chars) explaining the top reason(s) for the score, naming categories (and brand/government names if applicable).
8) "evidence": 1–6 short quotes/snippets from the markdown that justify the decision (remove PII; keep quotes short).
9) "impersonated_brands": brand/org names being mimicked (banks, wallets, gov portals), if any; else [].
10) "keywords": 3–12 topical keywords (no hashtags), in the original language; avoid duplicates.
11) "summary": <=400 chars, in the original language, neutral tone.
12) Be conservative: if signals are weak, lower the score and set unrelated categories to false.

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

    return ScrapeResult(markdown=md, length=len(md))

def _replicate_create_prediction(prompt: str) -> str:
    """Create prediction on Replicate; return prediction id."""
    url = f"{REPLICATE_API}/models/{REPLICATE_MODEL}/predictions"
    headers = {
        "Authorization": f"Bearer {REPLICATE_TOKEN}",
        "Content-Type": "application/json",
    }
    body = {
        "input": {
            "top_p": 1,
            "prompt": prompt,
            "max_tokens": 8024,
            "temperature": 0.1,
            "presence_penalty": 0,
            "frequency_penalty": 0,
        }
    }

    resp = requests.post(url, headers=headers, json=body, timeout=60)

    # Fallback if path form is unsupported in environment (use version param style)
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
    """Poll until succeeded/failed or timeout; return parsed JSON output."""
    headers = {
        "Authorization": f"Bearer {REPLICATE_TOKEN}",
        "Content-Type": "application/json",
    }
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
            # Replicate LLMs sometimes return array of strings → join
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

class Predictor(BasePredictor):
    def setup(self) -> None:
        """No heavy model to preload."""
        pass

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
        try:
            scraped = _scrape_markdown(url)
            print(scraped)
            if not scraped.markdown:
                return {"success": False, "url": url, "error": "No markdown from Firecrawl"}

            prompt = f"{PROMPT_HEADER}\n\nPage markdown:\n\n{scraped.markdown}"

            prediction_id = _replicate_create_prediction(prompt)
            parsed_json = _replicate_poll_prediction(prediction_id)

            # Light debug
            try:
                print(f"[RESULT] is_fraud={parsed_json.get('is_fraud')} "
                      f"risk={parsed_json.get('risk_score')} "
                      f"lang={parsed_json.get('language')}")
            except Exception:
                pass

            return {"success": True, "url": url, "result": parsed_json}

        except Exception as e:
            return {"success": False, "url": url, "error": str(e)}
