"""Pure CORS-policy analysis. Reports observable characteristics only —
"CORS policy characteristics", never "CORS vulnerability": without an
authenticated cross-origin request we cannot demonstrate exploitability,
only presence/reflection/wildcard/credentials as configured facts (see
paper/methodology.md).
"""

from dataclasses import dataclass

from crawler.models import CORSFetchResult

ANALYZER_VERSION = "0.1.0"


@dataclass(frozen=True)
class CORSResult:
    acao_present: bool
    acao_value: str | None
    acao_is_wildcard: bool
    acao_reflects_origin: bool
    acac_present: bool


def analyze_cors(fetch: CORSFetchResult) -> CORSResult:
    acao = fetch.acao_raw
    acac_raw = (fetch.acac_raw or "").strip().lower()
    return CORSResult(
        acao_present=acao is not None,
        acao_value=acao,
        acao_is_wildcard=(acao == "*"),
        acao_reflects_origin=(acao == fetch.tested_origin),
        acac_present=(acac_raw == "true"),
    )
