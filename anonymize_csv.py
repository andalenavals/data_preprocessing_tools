import pandas as pd
import re
import hashlib
from faker import Faker

fake = Faker()

# ══════════════════════════════════════════════════════════════════════════════
#  CONFIGURATION — edit these lists to match your data
# ══════════════════════════════════════════════════════════════════════════════

# Specific names/companies/clients to redact wherever they appear in any cell
SENSITIVE_ENTITIES = {
    "METRO":        "MILES",
    "Metro":         "Miles",
    "metro":       "miles",
    "myMETRO":  "myMILES",
    # add as many as you need...
}

# Column-name hints (case-insensitive substring match)
NAME_HINTS    = ["name", "full_name", "firstname", "lastname", "contact"]
EMAIL_HINTS   = ["email", "mail", "e-mail"]
PHONE_HINTS   = ["phone", "mobile", "tel", "fax", "cell"]
ADDRESS_HINTS = ["address", "street", "city", "zip", "postal", "country"]
COMPANY_HINTS = ["company", "employer", "org", "organization", "firm", "client"]
ID_HINTS      = ["ssn", "id", "passport", "national_id", "tax_id", "nif", "vat"]
IP_HINTS      = ["ip", "ip_address", "ipv4", "ipv6"]
IBAN_HINTS    = ["iban", "account", "bank"]

# ══════════════════════════════════════════════════════════════════════════════
#  REGEX PATTERNS  (for inline detection inside free-text cells)
# ══════════════════════════════════════════════════════════════════════════════

EMAIL_RE = re.compile(r'\b[\w.+-]+@[\w-]+\.[a-zA-Z]{2,}\b')
PHONE_RE = re.compile(r'\b(\+?[\d][\d\s\-().]{6,14}\d)\b')
IP_RE    = re.compile(r'\b\d{1,3}(?:\.\d{1,3}){3}\b')
IBAN_RE  = re.compile(r'\b[A-Z]{2}\d{2}[A-Z0-9]{1,30}\b')
URL_RE   = re.compile(r'https?://[^\s]+')


# ══════════════════════════════════════════════════════════════════════════════
#  ENTITY LIST  —  build regex + fake-replacement map at startup
# ══════════════════════════════════════════════════════════════════════════════

def _build_entity_map(entities: dict[str, str]) -> tuple[re.Pattern | None, dict[str, str]]:
    """
    Build a combined regex + a direct original→replacement map.
    Replacements are exactly what you specified in SENSITIVE_ENTITIES.
    """
    if not entities:
        return None, {}

    # Longest keys first → greedy match catches full names before partials
    sorted_keys = sorted(entities.keys(), key=len, reverse=True)

    # The fake_map now uses your exact replacements
    fake_map: dict[str, str] = {k: entities[k] for k in sorted_keys}

    pattern = re.compile(
        r'(?<!\w)(' +
        '|'.join(re.escape(k) for k in sorted_keys) +
        r')(?!\w)',
        re.IGNORECASE
    )
    return pattern, fake_map


def _replace_entity_match(match: re.Match, fake_map: dict[str, str]) -> str:
    """Return the fake replacement, preserving the key look-up case-insensitively."""
    original = match.group(0)
    for key in fake_map:
        if key.lower() == original.lower():
            return fake_map[key]
    return "REDACTED"


# ══════════════════════════════════════════════════════════════════════════════
#  COLUMN CLASSIFICATION
# ══════════════════════════════════════════════════════════════════════════════

def classify_column(col: str) -> str | None:
    col_l = col.lower()
    for hint in NAME_HINTS:
        if hint in col_l: return "name"
    for hint in EMAIL_HINTS:
        if hint in col_l: return "email"
    for hint in PHONE_HINTS:
        if hint in col_l: return "phone"
    for hint in ADDRESS_HINTS:
        if hint in col_l: return "address"
    for hint in COMPANY_HINTS:
        if hint in col_l: return "company"
    for hint in ID_HINTS:
        if hint in col_l: return "id"
    for hint in IP_HINTS:
        if hint in col_l: return "ip"
    for hint in IBAN_HINTS:
        if hint in col_l: return "iban"
    return None


# ══════════════════════════════════════════════════════════════════════════════
#  VALUE-LEVEL ANONYMISATION
# ══════════════════════════════════════════════════════════════════════════════

def anonymize_value(value, category: str, consistent_map: dict) -> str:
    if pd.isna(value) or str(value).strip() == "":
        return value

    key = (category, str(value))
    if key in consistent_map:
        return consistent_map[key]

    if   category == "name":    fake_val = fake.name()
    elif category == "email":   fake_val = fake.email()
    elif category == "phone":   fake_val = fake.phone_number()
    elif category == "address": fake_val = fake.address().replace("\n", ", ")
    elif category == "company": fake_val = fake.company()
    elif category == "ip":      fake_val = fake.ipv4()
    elif category == "iban":    fake_val = fake.iban()
    elif category == "id":
        fake_val = hashlib.sha256(str(value).encode()).hexdigest()[:10].upper()
    else:
        fake_val = "REDACTED"

    consistent_map[key] = fake_val
    return fake_val


def scrub_free_text(text: str, entity_pattern: re.Pattern | None,
                    fake_map: dict[str, str]) -> str:
    """
    Apply all scrubbing layers to a free-text cell:
      1. Named entity list (your specific names / companies)
      2. Regex patterns  (email, phone, IP, IBAN, URL)
    """
    if not isinstance(text, str):
        return text

    # 1 — named entities from your list
    if entity_pattern:
        text = entity_pattern.sub(
            lambda m: _replace_entity_match(m, fake_map), text
        )

    # 2 — pattern-based PII
    text = EMAIL_RE.sub(lambda _: fake.email(), text)
    text = PHONE_RE.sub(lambda _: fake.phone_number(), text)
    text = IP_RE.sub(lambda _: fake.ipv4(), text)
    text = IBAN_RE.sub(lambda _: fake.iban(), text)
    text = URL_RE.sub(lambda _: fake.url(), text)

    return text


# ══════════════════════════════════════════════════════════════════════════════
#  MAIN
# ══════════════════════════════════════════════════════════════════════════════


def anonymize_csv(input_path: str,
                  output_path: str,
                  sensitive_entities: dict[str, str] | None = None) -> None:

    entities       = sensitive_entities or SENSITIVE_ENTITIES
    entity_pattern, fake_map = _build_entity_map(entities)

    df             = pd.read_csv(input_path, dtype=str)
    consistent_map: dict = {}

    print(f"📂  Loaded {len(df)} rows × {len(df.columns)} columns")
    print(f"🔍  Watching for {len(entities)} named entities:")
    for original, replacement in entities.items():
        print(f"      '{original}' → '{replacement}'")

    for col in df.columns:
        category = classify_column(col)

        if category:
            df[col] = df[col].apply(
                lambda v: scrub_free_text(
                    anonymize_value(v, category, consistent_map),
                    entity_pattern, fake_map
                )
            )
            print(f"  ✅  [{category:10s}] {col}")
        else:
            df[col] = df[col].apply(
                lambda v: scrub_free_text(str(v) if pd.notna(v) else v,
                                          entity_pattern, fake_map)
            )
            print(f"  🔎  [free-text ] {col}")

    df.to_csv(output_path, index=False)
    print(f"\n✅  Anonymised CSV saved → {output_path}")


# ── CLI entry point ───────────────────────────────────────────────────────────
if __name__ == "__main__":
    import sys

    if len(sys.argv) >= 2:
        inp = sys.argv[1]
        out = sys.argv[2] if len(sys.argv) >= 3 else inp.replace(".csv", "_anonymized.csv")
        anonymize_csv(inp, out)
    else:
        print("Usage: python anonymize_csv.py input.csv [output.csv]")
