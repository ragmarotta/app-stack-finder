"""Rule Repository for hybrid signature management (Internal + Remote Webanalyze).

Implements Singleton, Lazy Loading, regex pre-compilation, and version template resolution.
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from app_stack_finder.core.models import TechCategory, TechItem
from app_stack_finder.detectors.base import clean_version

logger = logging.getLogger(__name__)

DEFAULT_DATA_DIR = Path(__file__).resolve().parent.parent / "data"
DEFAULT_RULES_PATH = DEFAULT_DATA_DIR / "technologies.json"

# Mapeamento oficial de categorias do Wappalyzer/Webanalyze para o TechCategory do sistema
WEBANALYZE_CAT_MAP: Dict[str, TechCategory] = {
    # Programming languages
    "27": TechCategory.LANGUAGES,
    # Frameworks & libraries
    "12": TechCategory.FRAMEWORKS,  # JavaScript frameworks
    "18": TechCategory.FRAMEWORKS,  # Web frameworks
    "26": TechCategory.FRAMEWORKS,  # Mobile frameworks
    "59": TechCategory.FRAMEWORKS,  # JavaScript libraries
    "66": TechCategory.FRAMEWORKS,  # UI frameworks
    "1": TechCategory.FRAMEWORKS,   # CMS
    "6": TechCategory.FRAMEWORKS,   # Ecommerce
    "11": TechCategory.FRAMEWORKS,  # Blogs
    "51": TechCategory.FRAMEWORKS,  # Page builders
    "57": TechCategory.FRAMEWORKS,  # Static site generator
    # Databases
    "3": TechCategory.DATABASES,    # Database managers
    "34": TechCategory.DATABASES,   # Databases
    # Infrastructure & Cloud
    "28": TechCategory.INFRASTRUCTURE,  # Operating systems
    "48": TechCategory.INFRASTRUCTURE,  # Network storage
    "60": TechCategory.INFRASTRUCTURE,  # Containers
    "62": TechCategory.INFRASTRUCTURE,  # PaaS
    "63": TechCategory.INFRASTRUCTURE,  # IaaS
    "64": TechCategory.INFRASTRUCTURE,  # Reverse proxies
    "65": TechCategory.INFRASTRUCTURE,  # Load balancers
    "88": TechCategory.INFRASTRUCTURE,  # Hosting
    # CI/CD
    "44": TechCategory.CICD,        # CI
    "47": TechCategory.CICD,        # Development
    # Security / WAF / CDN
    "16": TechCategory.SECURITY,    # Security
    "31": TechCategory.SECURITY,    # CDN
    "69": TechCategory.SECURITY,    # Authentication
    "70": TechCategory.SECURITY,    # SSL/TLS CAs
    "83": TechCategory.SECURITY,    # Browser fingerprinting
    # Web Servers
    "22": TechCategory.WEB_SERVERS, # Web servers
    "23": TechCategory.WEB_SERVERS, # Caching
    "33": TechCategory.WEB_SERVERS, # Web server extensions
}


@dataclass
class CompiledWebRule:
    """Regra de assinatura web pré-compilada para alta performance."""

    tech_name: str
    category: TechCategory
    regex: re.Pattern
    version_template: Optional[str] = None
    confidence: float = 1.0
    description: Optional[str] = None
    website: Optional[str] = None
    raw_pattern: str = ""


def parse_rule_pattern(raw_pattern: str) -> Tuple[str, Optional[str], float]:
    """
    Separa o padrão regex principal de modificadores do Wappalyzer/Webanalyze.
    Exemplo: 'nginx(?:/([\\d.]+))?\\;version:\\1\\;confidence:80'
    Retorna: (regex_str, version_template, confidence)
    """
    if not raw_pattern:
        return ("", None, 1.0)

    parts = raw_pattern.split(r"\;")
    pattern_str = parts[0]
    version_template: Optional[str] = None
    confidence = 1.0

    for part in parts[1:]:
        if part.startswith("version:"):
            version_template = part[len("version:"):]
        elif part.startswith("confidence:"):
            try:
                confidence = float(part[len("confidence:"):]) / 100.0
            except ValueError:
                pass

    return pattern_str, version_template, confidence


def resolve_version_template(template: Optional[str], match: re.Match) -> Optional[str]:
    """
    Resolve variáveis de versão dinâmicas no formato Wappalyzer (ex: '\\1', '\\1?GA4:').
    """
    if not template:
        return None

    # Suporte a ternário: \1?valor_se_verdadeiro:valor_se_falso
    m_ternary = re.match(r"^\\(\d+)\?([^:]*):(.*)$", template)
    if m_ternary:
        grp_idx = int(m_ternary.group(1))
        true_val = m_ternary.group(2)
        false_val = m_ternary.group(3)
        try:
            val = match.group(grp_idx)
            chosen = true_val if val else false_val
        except IndexError:
            chosen = false_val
        template = chosen

    # Substitui backreferences \1, \2, etc.
    res = template
    for i in range(1, len(match.groups()) + 1):
        g = match.group(i) or ""
        res = res.replace(f"\\{i}", g)

    res = res.strip()
    return clean_version(res) if res else None


class RuleRepository:
    """
    Repositório unificado de regras e assinaturas (Singleton & Lazy Loading).
    Mescla regras internas com regras remotas baixadas via Webanalyze.
    """

    _instance: Optional["RuleRepository"] = None

    def __init__(self, rules_path: Optional[Path] = None) -> None:
        self.rules_path: Path = Path(rules_path) if rules_path else DEFAULT_RULES_PATH
        self._loaded: bool = False
        self._has_remote_rules: bool = False
        self._warned_missing: bool = False

        # Regras pré-compiladas indexadas por seção
        self.header_rules: Dict[str, List[CompiledWebRule]] = {}
        self.cookie_rules: Dict[str, List[CompiledWebRule]] = {}
        self.meta_rules: Dict[str, List[CompiledWebRule]] = {}
        self.script_rules: List[CompiledWebRule] = []
        self.html_rules: List[CompiledWebRule] = []

        # Estatísticas
        self.total_remote_technologies: int = 0

    @classmethod
    def get_instance(cls, rules_path: Optional[Path] = None) -> "RuleRepository":
        """Retorna a instância Singleton do RuleRepository."""
        if cls._instance is None:
            cls._instance = cls(rules_path=rules_path)
        return cls._instance

    @classmethod
    def reset_instance(cls) -> None:
        """Reseta o Singleton (útil para testes unitários)."""
        cls._instance = None

    @property
    def is_loaded(self) -> bool:
        return self._loaded

    @property
    def has_remote_rules(self) -> bool:
        if not self._loaded:
            self.load_rules()
        return self._has_remote_rules

    def load_rules(self) -> None:
        """Carrega e indexa as regras sob demanda (Lazy Loading)."""
        if self._loaded:
            return

        self._loaded = True

        if not self.rules_path.exists():
            if not self._warned_missing:
                self._warned_missing = True
                logger.warning(
                    f"Arquivo de regras remotas não encontrado em '{self.rules_path}'. "
                    "A ferramenta operará normalmente utilizando as regras internas predefinidas. "
                    "Execute 'app-stack-finder --update-rules' para baixar as assinaturas completas."
                )
            self._has_remote_rules = False
            return

        try:
            content = self.rules_path.read_text(encoding="utf-8")
            data = json.loads(content)
            technologies = data.get("technologies", data)

            self._compile_technologies(technologies)
            self.total_remote_technologies = len(technologies)
            self._has_remote_rules = True
            logger.info(f"Regras remotas carregadas com sucesso: {self.total_remote_technologies} tecnologias.")

        except Exception as exc:
            logger.warning(
                f"Falha ao carregar regras remotas de '{self.rules_path}': {exc}. "
                "Operando apenas com as regras internas predefinidas."
            )
            self._has_remote_rules = False

    def _compile_technologies(self, technologies: Dict[str, Any]) -> None:
        """Pré-compila todas as expressões regulares do arquivo technologies.json."""
        for tech_name, tech_info in technologies.items():
            if not isinstance(tech_info, dict):
                continue

            cats = tech_info.get("cats", [])
            primary_cat = TechCategory.OTHER
            for cat_id in cats:
                if str(cat_id) in WEBANALYZE_CAT_MAP:
                    primary_cat = WEBANALYZE_CAT_MAP[str(cat_id)]
                    break

            desc = tech_info.get("description") or f"Identificado via assinatura Webanalyze ({tech_name})"
            website = tech_info.get("website")

            # 1. Headers
            hdrs = tech_info.get("headers")
            if isinstance(hdrs, dict):
                for hname, hpat in hdrs.items():
                    hname_lower = hname.lower()
                    patterns = hpat if isinstance(hpat, list) else [hpat]
                    for raw in patterns:
                        rule = self._create_compiled_rule(tech_name, primary_cat, raw, desc, website)
                        if rule:
                            self.header_rules.setdefault(hname_lower, []).append(rule)

            # 2. Cookies
            cookies = tech_info.get("cookies")
            if isinstance(cookies, dict):
                for cname, cpat in cookies.items():
                    cname_lower = cname.lower()
                    patterns = cpat if isinstance(cpat, list) else [cpat]
                    for raw in patterns:
                        rule = self._create_compiled_rule(tech_name, primary_cat, raw, desc, website)
                        if rule:
                            self.cookie_rules.setdefault(cname_lower, []).append(rule)

            # 3. Meta Tags
            metas = tech_info.get("meta")
            if isinstance(metas, dict):
                for mname, mpat in metas.items():
                    mname_lower = mname.lower()
                    patterns = mpat if isinstance(mpat, list) else [mpat]
                    for raw in patterns:
                        rule = self._create_compiled_rule(tech_name, primary_cat, raw, desc, website)
                        if rule:
                            self.meta_rules.setdefault(mname_lower, []).append(rule)

            # 4. Scripts
            scripts = tech_info.get("scripts")
            if isinstance(scripts, list):
                for raw in scripts:
                    rule = self._create_compiled_rule(tech_name, primary_cat, raw, desc, website)
                    if rule:
                        self.script_rules.append(rule)

            # 5. HTML Body
            htmls = tech_info.get("html")
            if isinstance(htmls, list):
                for raw in htmls:
                    rule = self._create_compiled_rule(tech_name, primary_cat, raw, desc, website)
                    if rule:
                        self.html_rules.append(rule)

    def _create_compiled_rule(
        self,
        tech_name: str,
        category: TechCategory,
        raw_pattern: Any,
        description: str,
        website: Optional[str],
    ) -> Optional[CompiledWebRule]:
        if not isinstance(raw_pattern, str):
            raw_pattern = str(raw_pattern or "")

        pattern_str, ver_tpl, confidence = parse_rule_pattern(raw_pattern)
        if not pattern_str:
            pattern_str = ".*"

        try:
            compiled_regex = re.compile(pattern_str, re.IGNORECASE)
            return CompiledWebRule(
                tech_name=tech_name,
                category=category,
                regex=compiled_regex,
                version_template=ver_tpl,
                confidence=confidence,
                description=description,
                website=website,
                raw_pattern=raw_pattern,
            )
        except re.error:
            return None

    def match_web_response(self, url: str, response_data: Dict[str, Any]) -> List[TechItem]:
        """
        Executa as regras web pré-compiladas contra cabeçalhos, cookies e corpo da resposta.
        Retorna as tecnologias identificadas.
        """
        if not self.has_remote_rules:
            return []

        items: List[TechItem] = []
        headers: Dict[str, str] = {k.lower(): str(v) for k, v in response_data.get("headers", {}).items()}
        cookies: Dict[str, str] = {k.lower(): str(v) for k, v in response_data.get("cookies", {}).items()}
        body: str = response_data.get("body", "")

        # 1. Match Headers
        for hname, hval in headers.items():
            rules = self.header_rules.get(hname, [])
            for rule in rules:
                m = rule.regex.search(hval)
                if m:
                    ver = resolve_version_template(rule.version_template, m)
                    items.append(
                        TechItem(
                            name=rule.tech_name,
                            category=rule.category,
                            version=ver,
                            source=f"Webanalyze Rule: Header ({hname})",
                            confidence=round(rule.confidence * 0.9, 2),
                            description=rule.description,
                        )
                    )

        # 2. Match Cookies
        set_cookie_raw = headers.get("set-cookie", "").lower()
        for cname, cval in cookies.items():
            rules = self.cookie_rules.get(cname, [])
            for rule in rules:
                m = rule.regex.search(cval)
                if m:
                    ver = resolve_version_template(rule.version_template, m)
                    items.append(
                        TechItem(
                            name=rule.tech_name,
                            category=rule.category,
                            version=ver,
                            source=f"Webanalyze Rule: Cookie ({cname})",
                            confidence=round(rule.confidence * 0.9, 2),
                            description=rule.description,
                        )
                    )

        # Se houver regras de cookies que combinem por Set-Cookie raw
        for cname, rules in self.cookie_rules.items():
            if cname not in cookies and cname in set_cookie_raw:
                for rule in rules:
                    m = rule.regex.search(set_cookie_raw)
                    if m:
                        ver = resolve_version_template(rule.version_template, m)
                        items.append(
                            TechItem(
                                name=rule.tech_name,
                                category=rule.category,
                                version=ver,
                                source=f"Webanalyze Rule: Cookie ({cname})",
                                confidence=round(rule.confidence * 0.9, 2),
                                description=rule.description,
                            )
                        )

        # 3. Match Meta Tags
        if body:
            meta_tags = re.findall(r'<meta[^>]+(?:name|property)=["\']([^"\']+)["\'][^>]+content=["\']([^"\']*)["\']', body, re.IGNORECASE)
            for mname, mval in meta_tags:
                rules = self.meta_rules.get(mname.lower(), [])
                for rule in rules:
                    m = rule.regex.search(mval)
                    if m:
                        ver = resolve_version_template(rule.version_template, m)
                        items.append(
                            TechItem(
                                name=rule.tech_name,
                                category=rule.category,
                                version=ver,
                                source=f"Webanalyze Rule: Meta ({mname})",
                                confidence=round(rule.confidence * 0.9, 2),
                                description=rule.description,
                            )
                        )

            # 4. Match Script Tags
            script_srcs = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', body, re.IGNORECASE)
            for src in script_srcs:
                for rule in self.script_rules:
                    m = rule.regex.search(src)
                    if m:
                        ver = resolve_version_template(rule.version_template, m)
                        items.append(
                            TechItem(
                                name=rule.tech_name,
                                category=rule.category,
                                version=ver,
                                source="Webanalyze Rule: Script Src",
                                confidence=round(rule.confidence * 0.9, 2),
                                description=rule.description,
                            )
                        )

            # 5. Match HTML Body (avalia primeiros 512KB para garantir eficiência extrema)
            body_sample = body[:524288]
            for rule in self.html_rules:
                m = rule.regex.search(body_sample)
                if m:
                    ver = resolve_version_template(rule.version_template, m)
                    items.append(
                        TechItem(
                            name=rule.tech_name,
                            category=rule.category,
                            version=ver,
                            source="Webanalyze Rule: HTML Body",
                            confidence=round(rule.confidence * 0.85, 2),
                            description=rule.description,
                        )
                    )

        return items
