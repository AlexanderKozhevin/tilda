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
        # existing
        "porn_erotica": {"type": "boolean"},
        "sexual_services": {"type": "boolean"},
        "drugs": {"type": "boolean"},
        "extremism": {"type": "boolean"},
        "casino_gambling": {"type": "boolean"},
        "weapons": {"type": "boolean"},
        "phishing": {"type": "boolean"},
        "government_services_impersonation": {"type": "boolean"},
        "redirect_buttons": {"type": "boolean"},
        "financial_scam_payouts": {"type": "boolean"},
        # NEW: extra categories mapped to your examples
        "profanity": {"type": "boolean"},                 # NEW
        "account_sales": {"type": "boolean"},             # NEW
        "explicit_nudity": {"type": "boolean"},           # NEW
        "adult_no_age_gate": {"type": "boolean"},         # NEW
        "erotic_spa_massage": {"type": "boolean"},        # NEW
        "webcam_onlyfans": {"type": "boolean"},           # NEW
        "poker_betting": {"type": "boolean"},             # NEW
        "casino_affiliate": {"type": "boolean"},          # NEW
        "alcohol_delivery": {"type": "boolean"},          # NEW
        "nicotine_vapes": {"type": "boolean"},            # NEW
        "hookah_tobacco": {"type": "boolean"},            # NEW
        "nitrous_oxide": {"type": "boolean"},             # NEW
        "amanita_mushrooms": {"type": "boolean"},         # NEW
        "cannabis_cbd": {"type": "boolean"},              # NEW
        "redirect_minimal_site": {"type": "boolean"}      # NEW
      },
      "required": [
        # existing required
        "porn_erotica","sexual_services","drugs","extremism","casino_gambling",
        "weapons","phishing","government_services_impersonation","redirect_buttons",
        "financial_scam_payouts",
        # NEW required
        "profanity","account_sales","explicit_nudity","adult_no_age_gate",
        "erotic_spa_massage","webcam_onlyfans","poker_betting","casino_affiliate",
        "alcohol_delivery","nicotine_vapes","hookah_tobacco","nitrous_oxide",
        "amanita_mushrooms","cannabis_cbd","redirect_minimal_site"
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
   Base set:
   - porn_erotica: порнография/эротика/намеренное возбуждение (не путать с проституцией).
   - sexual_services: проституция/эскорт/платные сексуальные услуги.
   - drugs: продажа/промо нелегальных рекреационных веществ (вкл. грибы) и атрибутики.
   - extremism: экстремистская символика/пропаганда/вербовка/одобрение насилия.
   - casino_gambling: казино/букмекеры/лотереи/ставки за деньги, их промо.
   - weapons: оружие/боеприпасы/боевые ножи/инструкции по обороту.
   - phishing: кража учётных данных/платежей, фальшивые логины/2FA/seed/wallet drains, подмена брендов/госуслуг.
   - government_services_impersonation: имитация гос.порталов/сервисов ради сбора данных/платежей.
   - redirect_buttons: обманные кнопки ("Скачать/Продолжить/Play") ведущие на сторонние сайты.
   - financial_scam_payouts: мгновенные выплаты/доходы за взнос, "быстро разбогатей", пирамиды.

   Extra set (new):
   - profanity: ненормативная лексика.
   - account_sales: продажа аккаунтов (соцсети/сервисы/игры и т.п.).
   - explicit_nudity: откровенные изображения/обнажённые части тела.
   - adult_no_age_gate: явный 18+ контент без возрастного ограничения/предупреждения.
   - erotic_spa_massage: эротический спа/массаж/шибари и пр., без явной проституции.
   - webcam_onlyfans: вебкам/OnlyFans/секс по видеосвязи.
   - poker_betting: покерные клубы/обучение покеру/ставки/букмекеры (может сосуществовать с casino_gambling).
   - casino_affiliate: партнёрские программы казино/промо-лендинги.
   - alcohol_delivery: доставка алкоголя/спирта.
   - nicotine_vapes: одноразовые вейпы/доставка никотиносодержащей продукции (IQOS и пр.).
   - hookah_tobacco: табак/кальян/кальянный кейтеринг.
   - nitrous_oxide: закись азота.
   - amanita_mushrooms: мухоморы/amanita.
   - cannabis_cbd: каннабис/КБД/конопля.
   - redirect_minimal_site: минималистичный «хаб-редирект»: очень мало текста/контента, 1–5 кнопок/ссылок, ведущих на внешние сайты; часто Tilda-поддомены.

   Set each boolean strictly from the markdown evidence (true if present/promoted; otherwise false).

6) Heuristics & exceptions:
   - profanity/explicit_nudity/adult_no_age_gate/erotic_spa_massage/webcam_onlyfans by themselves usually DO NOT imply "is_fraud" unless there is deception or illegal payment capture.
   - account_sales, nicotine_vapes, hookah_tobacco, nitrous_oxide, amanita_mushrooms, cannabis_cbd: mark categories if offered; fraud only if there are deceptive claims or illegal payment traps.
   - poker_betting/casino_affiliate: set alongside casino_gambling when appropriate.
   - redirect_minimal_site: if page is extremely short, mostly buttons/anchors, and many external links, set redirect_minimal_site=true and (if buttons are deceptive) redirect_buttons=true. This increases risk_score but does not automatically force is_fraud=true without deceptive patterns.
   - government/brand impersonation → phishing or government_services_impersonation and likely is_fraud=true.

7) Fraud rubric:
   - "is_fraud": true if the page aims to deceive or steal (e.g., phishing, impersonation, wallet drains, payout scams, deceptive redirects).
   - "risk_score":
       ≥0.90 clear fraud/phishing/impersonation with capture forms, seed/wallet requests, or multiple severe violations.
       0.70–0.89 strong evidence (explicit drug sales, prostitution ads, extremist propaganda, weapons trade, casino funnels, deceptive redirect hubs), or multiple red flags.
       0.40–0.69 partial/indirect evidence, suggestive language, weak signals, or minimalistic redirect hubs without explicit deception.
       <0.40 likely informational or benign.
8) "verdict": one concise sentence (<=220 chars) explaining the top reason(s) for the score, naming categories (and brand/government names if applicable).
9) "evidence": 1–6 short quotes/snippets from the markdown that justify the decision (remove PII; keep quotes short).
10) "impersonated_brands": brand/org names being mimicked (banks, wallets, gov portals), if any; else [].
11) "keywords": 3–12 topical keywords (no hashtags), in the original language; avoid duplicates.
12) "summary": <=400 chars, in the original language, neutral tone.
13) Be conservative: if signals are weak, lower the score and set unrelated categories to false.

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
