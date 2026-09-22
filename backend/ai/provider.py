"""AI Provider Abstraction and Implementations for GRC Security Intelligence.

Provides:
- AIProvider: Abstract base class for replaceable intelligence providers.
- GeminiAIProvider: Primary Generative AI Provider using Google's official Gemini API / Google GenAI SDK.
- RuleAssistedAIProvider: Built-in deterministic local intelligence analyzer (fallback).
- ExternalLLMProvider: Optional OpenAI-compatible provider.
- get_ai_provider: Factory function resolving configured provider.
"""

import os
import json
import logging
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import List, Dict, Any, Optional

from .schemas import (
    NormalizedSecurityContext,
    AIAnalysisResult,
    RemediationSteps,
    RecommendedControl,
)
from .prompts import SYSTEM_PROMPT, generate_analysis_prompt

logger = logging.getLogger("ai_grc.ai_provider")


def ensure_env_loaded():
    """Ensure environment variables from backend/.env or root .env are loaded."""
    try:
        from dotenv import load_dotenv
        current_dir = os.path.dirname(os.path.abspath(__file__))
        backend_dir = os.path.dirname(current_dir)
        backend_env = os.path.join(backend_dir, ".env")
        should_override = not bool(os.environ.get("GEMINI_API_KEY", "").strip())
        if os.path.isfile(backend_env):
            load_dotenv(dotenv_path=backend_env, override=should_override)
        root_env = os.path.join(os.path.dirname(backend_dir), ".env")
        if os.path.isfile(root_env):
            load_dotenv(dotenv_path=root_env, override=should_override)
        load_dotenv(override=should_override)
    except Exception:
        pass


ensure_env_loaded()


class AIProviderError(Exception):
    """Base error raised when an AI provider fails, times out, or returns invalid output."""
    pass


class AIProviderTransientError(AIProviderError):
    """Transient error: network timeout, 503, 429 rate-limit — chain should advance."""
    pass


class AIProviderFatalError(AIProviderError):
    """Fatal error: missing API key, 401 unauthorized, configuration error — chain advances."""
    pass


@dataclass
class ProviderAttempt:
    """Audit record for a single provider attempt within ProviderChain."""
    provider_name: str
    model_name: str
    succeeded: bool
    error_type: Optional[str] = None
    error_message: Optional[str] = None


CREDENTIAL_KEY_VAL = re.compile(
    r"(password|passwd|pwd|secret|api_key|apikey|token|bearer|auth|private_key)\s*[:=]\s*([^\s,;]+)",
    re.IGNORECASE,
)
DATABASE_URI_PATTERN = re.compile(
    r"([a-zA-Z0-9+]+://)([^:]+):([^@]+)@([^\s/]+/[^\s]*)",
    re.IGNORECASE,
)
PRIVATE_KEY_PATTERN = re.compile(
    r"-----BEGIN [A-Z ]+ PRIVATE KEY-----.*?-----END [A-Z ]+ PRIVATE KEY-----",
    re.DOTALL,
)
API_KEY_PATTERNS = re.compile(
    r"\b(sk-[a-zA-Z0-9_-]{8,}|gsk_[a-zA-Z0-9_-]{8,}|AIza[a-zA-Z0-9_-]{15,})\b"
)


def _sanitize_compact(text: Optional[str], max_len: int = 200) -> str:
    """Sanitize free text of potential passwords, tokens, or credentials and truncate."""
    if not text:
        return ""
    sanitized = CREDENTIAL_KEY_VAL.sub(r"\1=[REDACTED]", str(text))
    sanitized = DATABASE_URI_PATTERN.sub(r"\1\2:[REDACTED]@\4", sanitized)
    sanitized = PRIVATE_KEY_PATTERN.sub("[REDACTED PRIVATE KEY]", sanitized)
    sanitized = API_KEY_PATTERNS.sub("[REDACTED KEY]", sanitized)
    sanitized = sanitized.replace("\n", " ").strip()
    if len(sanitized) > max_len:
        return sanitized[:max_len - 3] + "..."
    return sanitized


def validate_and_sanitize_result(
    result: AIAnalysisResult,
    context: NormalizedSecurityContext,
) -> AIAnalysisResult:
    """Validate semantic constraints on AI model output (shared across all providers)."""
    # Standardize priority
    if result.priority not in ["Critical", "High", "Medium", "Low"]:
        result.priority = "Medium"

    # Clamp confidence to valid range
    if result.confidence < 0.0:
        result.confidence = 0.0
    elif result.confidence > 1.0:
        result.confidence = 1.0

    # Semantic rule: If CVSS or vuln is missing, confidence cannot be artificially high
    if context.cvss_score is None and result.confidence > 0.75:
        result.confidence = 0.70

    # Semantic rule: High or Critical risk or missing critical info requires human review
    if (
        context.inherent_risk_score >= 12
        or context.residual_risk_score >= 8
        or (context.asset_environment and context.asset_environment.lower() == "production")
        or context.cvss_score is None
        or context.cve is None
        or context.is_criticality_default
        or context.is_exposure_default
    ):
        result.human_review_required = True
        if not result.human_review_reasons:
            result.human_review_reasons = [
                "Human validation recommended due to elevated risk, production environment, or incomplete evidence."
            ]

    return result


class AIProvider(ABC):
    """Abstract Base Class for replaceable AI security intelligence providers."""

    @abstractmethod
    def analyze_finding(self, context: NormalizedSecurityContext) -> AIAnalysisResult:
        """Analyze normalized security context and return structured intelligence."""
        pass


# ---------------------------------------------------------------------------
# Rule-Assisted Local AI Provider (Deterministic Local Fallback)
# ---------------------------------------------------------------------------

class RuleAssistedAIProvider(AIProvider):
    """Built-in local security intelligence analyzer (Deterministic Fallback).

    Provides transparent, evidence-based analysis translating technical findings
    into technical and non-technical explanations, business impacts, tiered remediation,
    and platform control recommendations without external API dependencies.

    Note: This is a deterministic expert-system fallback, NOT a generative AI model.
    """

    MODEL_NAME = "rule-assisted-grc-v1"

    @property
    def model_name(self) -> str:
        return self.MODEL_NAME

    def analyze_finding(self, context: NormalizedSecurityContext) -> AIAnalysisResult:
        title = context.risk_title or "Security Finding"
        title_lower = title.lower()
        service = (context.service or "").lower()
        port = context.port
        crit = (context.asset_criticality or "Medium").capitalize()
        env = (context.asset_environment or "Production").capitalize()
        exposure = (context.asset_exposure or "Internal").capitalize()

        # 1. Simple explanation & Why it matters (Tailored by service/finding)
        if "postgresql" in title_lower or "database" in title_lower or "5432" in str(port):
            simple_exp = (
                f"A database service ({context.product or 'PostgreSQL'}) is accessible over the network "
                f"on port {port or 5432}. If this access is unrestricted or unneeded, unauthorized actors "
                f"may attempt to query, manipulate, or brute-force the database."
            )
            why_matters = (
                "Databases store vital organizational and application records. Exposing listening database "
                "ports across network boundaries expands the logical attack surface and bypasses application-tier "
                "safeguards if network segregation is insufficient."
            )
            data_impact = "Potential unauthorized data inspection or exfiltration if database authentication is breached (Inferred: actual data sensitivity is unverified)."
            disruption_impact = "Potential database service degradation or downtime if subjected to high-volume connection requests or Denial of Service."
            service_remediation_immediate = (
                f"Restrict access to TCP/{port or 5432} using the organization's approved network security controls "
                "strictly to authorized application server IP addresses."
            )
            service_remediation_perm = (
                f"Verify that {context.product or 'PostgreSQL'} is configured to listen only on necessary "
                "interfaces, enforce TLS encryption for all client connections, and deploy supported vendor updates."
            )
        elif "smb" in title_lower or "445" in str(port) or "139" in str(port):
            simple_exp = (
                "A file-sharing service (SMB) is listening on the network. If file sharing is "
                "not required for this system's role, leaving it exposed allows network users to inspect "
                "network shares or exploit legacy protocol weaknesses."
            )
            why_matters = (
                "SMB services have historically been targets for lateral movement, credential relaying, "
                "and exploits. Unprotected SMB ports present significant lateral exposure."
            )
            data_impact = "Potential unauthorized file share access or privilege escalation (Inferred: shared volume contents are unverified)."
            disruption_impact = "Potential lateral movement or ransomware propagation across network segments."
            service_remediation_immediate = "Block inbound SMB ports (TCP 445 and 139) at the segment boundary for non-file-server hosts using approved firewall rules."
            service_remediation_perm = "Disable legacy SMB protocols, enforce SMB signing and encryption, and restrict administrative shares."
        elif "rpc" in title_lower or "135" in str(port):
            simple_exp = (
                "Microsoft Remote Procedure Call (RPC) endpoint mapper is open on the network. This service "
                "helps systems communicate with internal OS components, but should typically not be reachable "
                "outside trusted administrative subnets."
            )
            why_matters = (
                "Exposed RPC services provide reconnaissance information regarding registered system interfaces "
                "and can be exploited via remote buffer overflow or authentication bypass vulnerabilities."
            )
            data_impact = "Potential system reconnaissance and enumeration of internal endpoints by untrusted hosts."
            disruption_impact = "Potential host compromise or service disruption if remote RPC vulnerabilities are targeted."
            service_remediation_immediate = "Restrict access to TCP/135 using network firewall access control lists (ACLs)."
            service_remediation_perm = "Segment domain management interfaces into isolated management VLANs accessible only via jump boxes."
        elif "netbios" in title_lower or "137" in str(port):
            simple_exp = (
                "A NetBIOS name resolution service is broadcasting on the network. This legacy protocol "
                "can leak system and domain information to other devices on the local segment."
            )
            why_matters = (
                "NetBIOS name service broadcasts can be spoofed or poisoned by local attackers "
                "to capture user authentication hashes."
            )
            data_impact = "Potential credential hash capture and domain name spoofing by adversaries on the local subnet."
            disruption_impact = "Potential unauthorized lateral reconnaissance across domain members."
            service_remediation_immediate = "Disable NetBIOS over TCP/IP on network adapters if modern DNS is functional."
            service_remediation_perm = "Decommission legacy NetBIOS and WINS across group policy in favor of secure DNS."
        elif "vmware" in title_lower or "902" in str(port):
            simple_exp = (
                "A virtualization management service (VMware Authentication Daemon) is listening on the network. "
                "This allows administrative control over virtual machines."
            )
            why_matters = (
                "Virtualization management infrastructure controls host hypervisors and guest workloads. Unrestricted "
                "network reachability creates high-consequence exposure."
            )
            data_impact = "Potential unauthorized management access to underlying virtual machines and storage volumes."
            disruption_impact = "Potential hypervisor compromise leading to multi-tenant service outages."
            service_remediation_immediate = "Isolate VMware management traffic (TCP 902) to dedicated, out-of-band management networks."
            service_remediation_perm = "Enforce strong multi-factor authentication, administrative access logging, and regular hypervisor patching."
        else:
            simple_exp = (
                f"A network service ({service or 'network service'}) was detected listening on port {port or 'unknown'}. "
                "Unnecessary or unmonitored listening services expand the attack surface available to unauthorized parties."
            )
            why_matters = (
                "Every active network port is a potential entry point. Services running outdated versions, weak "
                "default configurations, or inadequate authentication can be exploited to gain logical access."
            )
            data_impact = "Potential unauthorized data access if unauthenticated or vulnerable endpoints are exposed."
            disruption_impact = "Potential service interruption or denial of service against the listening application."
            service_remediation_immediate = f"Restrict access to port {port or 'this port'} using the organization's approved network security controls."
            service_remediation_perm = "Audit host configuration, disable unneeded daemons, and apply current vendor-supported updates."

        # 2. Severity Interpretation
        if context.cvss_score:
            score = context.cvss_score
            ver = context.cvss_version or "3.1"
            if score >= 9.0:
                sev_meaning = "indicates a critical vulnerability with severe potential for complete system compromise or unauthenticated remote takeover."
            elif score >= 7.0:
                sev_meaning = "indicates a high-severity flaw that could allow significant privilege escalation or unauthorized operational impact."
            elif score >= 4.0:
                sev_meaning = "indicates moderate severity, often requiring specific user interaction or existing local access to exploit."
            else:
                sev_meaning = "indicates low severity with limited direct impact or high exploitation complexity."

            sev_exp = (
                f"The finding carries an official CVSS {ver} score of {score:.1f}, which {sev_meaning} "
                f"Confidence in this CVE association is classified as '{context.cve_confidence or 'Candidate'}'. "
                f"Official rule-based risk rating: {context.inherent_risk_level} (Inherent Score: {context.inherent_risk_score})."
            )
        else:
            sev_exp = (
                f"An official CVSS score is not available for this finding. Technical severity is evaluated as {context.inherent_risk_level} "
                "based on the exposed network service profile, port sensitivity, and heuristic risk rules."
            )

        # 3. Dynamic Risk Factors (with explicit default fallback marking)
        crit_msg = (
            f"Asset Business Criticality is assumed as '{crit}' by default (unspecified in asset intelligence; actual criticality is unverified)."
            if context.is_criticality_default else
            f"Asset Business Criticality is rated {crit} ({'elevating potential operational impact' if crit in ['Critical', 'High'] else 'standard baseline impact'})."
        )
        env_msg = (
            f"Operating Environment is assumed as '{env}' by default (unspecified in asset intelligence; actual environment is unverified)."
            if context.is_environment_default else
            f"Operating Environment is designated as {env} ({'requiring strict uptime and rigorous change verification' if env == 'Production' else 'non-production test environment'})."
        )
        exp_msg = (
            f"Network Exposure is assumed as '{exposure}' by default (unspecified in asset intelligence; actual boundary exposure is unverified)."
            if context.is_exposure_default else
            f"Network Exposure is classified as {exposure} ({'external Internet visibility significantly increases discovery probability' if exposure == 'External' else 'internal network boundary provides defense-in-depth isolation'})."
        )

        risk_factors = [crit_msg, env_msg, exp_msg]
        if context.cve:
            risk_factors.append(f"Correlated with known CVE: {context.cve} (Confidence: {context.cve_confidence or 'Unverified'}).")
        if context.cvss_score:
            risk_factors.append(f"Official CVSS metric: {context.cvss_score} ({context.cvss_version or 'v3.1'}).")

        if context.existing_controls:
            ctrl_names = ", ".join(c.get("name", "Control") for c in context.existing_controls)
            risk_factors.append(f"Mitigating controls currently linked: {ctrl_names}.")
        else:
            risk_factors.append("No active security controls currently associated with this risk in the platform.")

        # 4. Potential Business Impact
        business_impact = [
            data_impact,
            disruption_impact,
            "Regulatory / Compliance Impact: Unmitigated exposures may fail baseline controls under NIST CSF 2.0 (PR.IR-01, PR.PS-01) and ISO/IEC 27001:2022 (A.8.20).",
            "Note on Factuality: Business impacts above represent inferred potential risks based on service type. Specific business loss depends on the unverified sensitivity of data on this host."
        ]

        # 5. Recommendations
        recommendations = [
            f"Review business necessity of running {context.service or 'this service'} on {env} asset {context.risk_title.split()[0] if context.risk_title else 'target'}.",
            "Implement network access controls restricting inbound traffic strictly to authorized client IP ranges.",
            "Ensure host operating system and service binaries are updated to current vendor-supported releases."
        ]
        if context.asset_business_function:
            recommendations.append(f"Align remediation timeline with the documented business function: '{context.asset_business_function}'.")

        # 6. Structured Remediation (3 tiers)
        validation_steps = [
            f"Re-scan the target host using the network scanner to verify port {port or 'affected port'} is no longer accessible from untrusted zones.",
            "Verify that authorized business applications continue to communicate normally without error.",
            "Review audit logs to ensure dropped connection attempts are recorded as expected."
        ]
        remediation = RemediationSteps(
            immediate_mitigation=[service_remediation_immediate],
            permanent_remediation=[service_remediation_perm],
            validation=validation_steps
        )

        # 7. Recommended Controls from Catalog
        recommended_controls = []
        avail = context.available_controls or []
        if any("firewall" in c.lower() for c in avail):
            recommended_controls.append(RecommendedControl(
                name="Firewall",
                reason="Enforces network packet filtering to block unauthorized inbound connections to exposed ports."
            ))
        if any("segmentation" in c.lower() for c in avail):
            recommended_controls.append(RecommendedControl(
                name="Network Segmentation",
                reason="Isolates the asset into a dedicated VLAN, preventing lateral movement from untrusted subnets."
            ))
        if any("patch" in c.lower() for c in avail):
            recommended_controls.append(RecommendedControl(
                name="Patch Management",
                reason="Deploys vendor security updates systematically to eliminate software vulnerabilities."
            ))
        if any("access control" in c.lower() for c in avail):
            recommended_controls.append(RecommendedControl(
                name="Access Control",
                reason="Enforces least privilege and authentication rules before granting access to service endpoints."
            ))

        if not recommended_controls:
            recommended_controls.append(RecommendedControl(
                name="Network Segmentation",
                reason="Restricts service exposure across enterprise subnets."
            ))

        # 8. Confidence Score Calculation
        confidence = 0.60
        human_review_reasons = []

        if context.cvss_score:
            confidence += 0.15
        else:
            human_review_reasons.append("Official CVSS technical score is unavailable; severity is estimated heuristically.")

        if context.cve and context.cve_confidence == "Confirmed":
            confidence += 0.10
        elif context.cve:
            confidence += 0.05
        else:
            human_review_reasons.append("Exact software version is unverified; patch applicability requires confirmation.")

        if context.asset_business_function:
            confidence += 0.05
        else:
            human_review_reasons.append("Asset business function is not documented; potential operational impact requires context.")

        if context.is_criticality_default or context.is_exposure_default:
            confidence -= 0.05
            human_review_reasons.append("Asset intelligence (criticality/exposure) is using default baseline assumptions; human verification recommended.")

        confidence = round(max(0.30, min(0.95, confidence)), 2)

        # 9. AI Priority (Advisory contextual prioritization)
        if (context.cvss_score and context.cvss_score >= 8.5) or crit == "Critical" or context.inherent_risk_score >= 12:
            ai_priority = "Critical"
        elif (context.cvss_score and context.cvss_score >= 7.0) or crit == "High" or context.inherent_risk_score >= 8:
            ai_priority = "High"
        elif (context.cvss_score and context.cvss_score >= 4.0) or crit == "Medium" or context.inherent_risk_score >= 4:
            ai_priority = "Medium"
        else:
            ai_priority = "Low"

        # 10. Human Review Flag
        human_review_required = False
        if ai_priority in ["Critical", "High"]:
            human_review_required = True
            human_review_reasons.append(f"{ai_priority} priority security finding warrants human validation before taking action.")
        if env == "Production":
            human_review_required = True
            human_review_reasons.append("Asset is in Production environment; remediation must follow approved change control.")
        if confidence < 0.80:
            human_review_required = True
            human_review_reasons.append(f"AI confidence is {confidence}; human analyst should verify missing data points.")
        if context.is_criticality_default or context.is_exposure_default:
            human_review_required = True

        return AIAnalysisResult(
            priority=ai_priority,
            simple_explanation=simple_exp,
            why_it_matters=why_matters,
            severity_explanation=sev_exp,
            risk_factors=risk_factors,
            potential_business_impact=business_impact,
            recommendation=recommendations,
            remediation=remediation,
            recommended_controls=recommended_controls,
            confidence=confidence,
            human_review_required=human_review_required,
            human_review_reasons=human_review_reasons,
            model_name=self.MODEL_NAME
        )


# ---------------------------------------------------------------------------
# Google Gemini Primary Generative AI Provider
# ---------------------------------------------------------------------------

class GeminiAIProvider(AIProvider):
    """Primary Generative AI Provider using Google's official Gemini API / Google GenAI SDK.

    Utilizes native Gemini structured outputs (response_schema=AIAnalysisResult) to generate
    dual-audience cybersecurity intelligence. Supports configurable models (default: gemini-3.8-flash)
    and robust deterministic local fallback to RuleAssistedAIProvider when unconfigured or unavailable.
    """

    DEFAULT_MODEL = "gemini-3.8-flash"
    DEFAULT_TIMEOUT_SECONDS = 8
    DEFAULT_MAX_RETRIES = 1

    def __init__(
        self,
        api_key: Optional[str] = None,
        model_name: Optional[str] = None,
        fallback_enabled: bool = True,
        client: Optional[Any] = None,
        timeout_seconds: Optional[int] = None,
        max_retries: Optional[int] = None,
    ):
        self._explicit_key = api_key is not None
        if api_key is not None:
            self.api_key = api_key.strip()
        else:
            ensure_env_loaded()
            self.api_key = os.getenv("GEMINI_API_KEY", "").strip()

        if model_name is not None:
            self.model_name = model_name.strip()
        else:
            ensure_env_loaded()
            self.model_name = os.getenv("GEMINI_MODEL", self.DEFAULT_MODEL).strip()

        if timeout_seconds is not None:
            self.timeout_seconds = timeout_seconds
        else:
            try:
                self.timeout_seconds = int(os.getenv("GEMINI_TIMEOUT_SECONDS", str(self.DEFAULT_TIMEOUT_SECONDS)))
            except ValueError:
                self.timeout_seconds = self.DEFAULT_TIMEOUT_SECONDS

        if max_retries is not None:
            self.max_retries = max_retries
        else:
            try:
                self.max_retries = int(os.getenv("GEMINI_MAX_RETRIES", str(self.DEFAULT_MAX_RETRIES)))
            except ValueError:
                self.max_retries = self.DEFAULT_MAX_RETRIES

        self.fallback_enabled = fallback_enabled
        self._client = client
        self._local_fallback = RuleAssistedAIProvider()

    def _build_http_options(self):
        """Construct HttpOptions with short deadline and disabled/minimal retries.

        Note: Google GenAI API requires server deadline >= 10s (10000ms).
        Setting retry_options attempts=1 ensures failures (503, timeouts) return
        promptly instead of retrying with exponential backoff.
        """
        try:
            from google.genai import types
            timeout_ms = max(10000, self.timeout_seconds * 1000)
            client_timeout_sec = float(max(10, self.timeout_seconds))
            retry_opts = types.HttpRetryOptions(attempts=max(1, self.max_retries))
            return types.HttpOptions(
                timeout=timeout_ms,
                client_args={"timeout": client_timeout_sec},
                retry_options=retry_opts,
            )
        except Exception as e:
            logger.debug(f"Could not build HttpOptions: {e}")
            return None

    def _get_client(self):
        if self._client is not None:
            return self._client
        if not self.api_key and not self._explicit_key:
            ensure_env_loaded()
            self.api_key = os.getenv("GEMINI_API_KEY", "").strip()
        if not self.api_key:
            raise AIProviderError("GEMINI_API_KEY environment variable is not configured or empty.")
        try:
            from google import genai
            http_options = self._build_http_options()
            if http_options is not None:
                return genai.Client(api_key=self.api_key, http_options=http_options)
            return genai.Client(api_key=self.api_key)
        except Exception as err:
            raise AIProviderError(f"Failed to initialize Google GenAI client: {err}")

    def analyze_finding(self, context: NormalizedSecurityContext) -> AIAnalysisResult:
        """Analyze security finding using Gemini LLM with structured output."""
        try:
            client = self._get_client()
            prompt = generate_analysis_prompt(
                context.model_dump() if hasattr(context, "model_dump") else context.dict()
            )

            from google.genai import types
            http_options = self._build_http_options()
            config_kwargs = {
                "system_instruction": SYSTEM_PROMPT,
                "response_mime_type": "application/json",
                "response_schema": AIAnalysisResult,
                "temperature": 0.2,
            }
            if http_options is not None:
                config_kwargs["http_options"] = http_options

            config = types.GenerateContentConfig(**config_kwargs)

            response = client.models.generate_content(
                model=self.model_name,
                contents=prompt,
                config=config,
            )

            if not response or not response.text:
                raise AIProviderError("Gemini API returned an empty or null response.")

            parsed_data = json.loads(response.text)
            parsed_data["model_name"] = self.model_name
            result = AIAnalysisResult(**parsed_data)

            return self._validate_and_sanitize_result(result, context)

        except Exception as err:
            logger.warning(f"GeminiAIProvider encountered error: {err}")
            if self.fallback_enabled:
                logger.info("Engaging RuleAssistedAIProvider deterministic local fallback.")
                fallback_result = self._local_fallback.analyze_finding(context)
                fallback_result.human_review_required = True
                fallback_result.human_review_reasons.append(
                    f"Gemini LLM unavailable ({str(err)}); analysis generated via local rule-assisted fallback."
                )
                fallback_result.model_name = f"{self.model_name} (fallback: {self._local_fallback.MODEL_NAME})"
                return fallback_result
            else:
                raise AIProviderError(f"Gemini AI provider failed: {err}") from err

    def _validate_and_sanitize_result(
        self,
        result: AIAnalysisResult,
        context: NormalizedSecurityContext,
    ) -> AIAnalysisResult:
        """Validate semantic constraints on Gemini model output."""
        return validate_and_sanitize_result(result, context)


# ---------------------------------------------------------------------------
# Optional External LLM Provider (Legacy OpenAI-compatible / Custom REST)
# ---------------------------------------------------------------------------

class ExternalLLMProvider(AIProvider):
    """External HTTP/LLM Provider using OpenAI-compatible or custom REST endpoints."""

    def __init__(
        self,
        api_key: Optional[str] = None,
        endpoint: Optional[str] = None,
        model_name: Optional[str] = None
    ):
        self.api_key = api_key or os.getenv("AI_API_KEY")
        self.endpoint = endpoint or os.getenv("AI_ENDPOINT", "https://api.openai.com/v1/chat/completions")
        self.model_name = model_name or os.getenv("AI_MODEL", "gpt-4o-mini")

    def analyze_finding(self, context: NormalizedSecurityContext) -> AIAnalysisResult:
        if not self.api_key and "localhost" not in self.endpoint and "127.0.0.1" not in self.endpoint:
            raise AIProviderError("AI_API_KEY is not configured for ExternalLLMProvider.")

        import requests
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.api_key or ''}"
        }

        prompt = generate_analysis_prompt(
            context.model_dump() if hasattr(context, "model_dump") else context.dict()
        )
        payload = {
            "model": self.model_name,
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": prompt}
            ],
            "temperature": 0.2,
            "response_format": {"type": "json_object"}
        }

        try:
            resp = requests.post(self.endpoint, headers=headers, json=payload, timeout=12)
            if resp.status_code != 200:
                raise AIProviderError(f"AI provider HTTP error {resp.status_code}: {resp.text}")

            data = resp.json()
            raw_content = data["choices"][0]["message"]["content"]
            parsed_json = json.loads(raw_content)

            parsed_json["model_name"] = self.model_name
            return AIAnalysisResult(**parsed_json)

        except (requests.RequestException, KeyError, json.JSONDecodeError, ValueError) as err:
            logger.error(f"External AI Provider error: {err}")
            raise AIProviderError(f"Failed to obtain valid AI analysis from provider: {str(err)}")


# ---------------------------------------------------------------------------
# OpenAI-Compatible Providers & Production Implementations (OpenAI & Groq)
# ---------------------------------------------------------------------------

def make_strict_json_schema(schema_dict: dict) -> dict:
    """Recursively transform JSON schema for OpenAI/Groq strict Structured Outputs.

    OpenAI/Groq strict mode requirements:
    1. Every object schema (root, nested, under $defs) must have additionalProperties: false.
    2. Every object schema with properties must list all its properties in required.
    3. Traverses nested dictionaries, lists, and schema definitions without mutating the input.
    """
    import copy
    schema = copy.deepcopy(schema_dict)

    def _walk(node):
        if not isinstance(node, dict):
            return
        if node.get("type") == "object" or "properties" in node:
            node["additionalProperties"] = False
            if "properties" in node:
                node["required"] = list(node["properties"].keys())
        for v in node.values():
            if isinstance(v, dict):
                _walk(v)
            elif isinstance(v, list):
                for item in v:
                    if isinstance(item, dict):
                        _walk(item)

    _walk(schema)
    return schema


class _OpenAICompatibleProvider(AIProvider):
    """Base provider for OpenAI-compatible REST endpoints using structured outputs."""

    DEFAULT_MODEL: str = ""
    DEFAULT_TIMEOUT_SECONDS: int = 10
    MODEL_ENV: str = ""
    KEY_ENV: str = ""
    DEFAULT_ENDPOINT: str = ""
    ENDPOINT_ENV: str = ""
    TIMEOUT_ENV: str = ""

    def __init__(
        self,
        api_key: Optional[str] = None,
        model_name: Optional[str] = None,
        endpoint: Optional[str] = None,
        timeout_seconds: Optional[int] = None,
    ):
        ensure_env_loaded()
        self._explicit_key = api_key is not None
        if api_key is not None:
            self.api_key = api_key.strip()
        else:
            self.api_key = os.getenv(self.KEY_ENV, "").strip() if self.KEY_ENV else ""

        if model_name is not None and model_name.strip():
            self._api_model = model_name.strip()
        else:
            env_model = os.getenv(self.MODEL_ENV, "").strip() if self.MODEL_ENV else ""
            self._api_model = env_model or self.DEFAULT_MODEL

        if endpoint is not None:
            self.endpoint = endpoint.strip()
        else:
            self.endpoint = (
                os.getenv(self.ENDPOINT_ENV, self.DEFAULT_ENDPOINT).strip()
                if self.ENDPOINT_ENV
                else self.DEFAULT_ENDPOINT
            ) or self.DEFAULT_ENDPOINT

        if timeout_seconds is not None:
            self.timeout_seconds = timeout_seconds
        else:
            try:
                env_timeout = (
                    os.getenv(self.TIMEOUT_ENV, str(self.DEFAULT_TIMEOUT_SECONDS))
                    if self.TIMEOUT_ENV
                    else str(self.DEFAULT_TIMEOUT_SECONDS)
                )
                self.timeout_seconds = int(env_timeout)
            except ValueError:
                self.timeout_seconds = self.DEFAULT_TIMEOUT_SECONDS

    @property
    def model_name(self) -> str:
        return self._api_model

    def analyze_finding(self, context: NormalizedSecurityContext) -> AIAnalysisResult:
        if not self.api_key:
            raise AIProviderFatalError(
                f"{self.KEY_ENV or 'API key'} environment variable is not configured or empty for {type(self).__name__}."
            )

        import requests

        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.api_key}",
        }

        prompt = generate_analysis_prompt(
            context.model_dump() if hasattr(context, "model_dump") else context.dict()
        )

        schema = make_strict_json_schema(AIAnalysisResult.model_json_schema())
        payload = {
            "model": self._api_model,
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": prompt},
            ],
            "temperature": 0.2,
            "response_format": {
                "type": "json_schema",
                "json_schema": {
                    "name": "ai_analysis_result",
                    "strict": True,
                    "schema": schema,
                },
            },
        }

        resp = None
        try:
            resp = requests.post(
                self.endpoint,
                headers=headers,
                json=payload,
                timeout=self.timeout_seconds,
            )
        except requests.Timeout as err:
            raise AIProviderTransientError(
                f"{type(self).__name__} request timed out after {self.timeout_seconds}s"
            ) from err
        except requests.RequestException as err:
            raise AIProviderTransientError(
                f"{type(self).__name__} network error: {_sanitize_compact(str(err))}"
            ) from err

        # Fallback to json_object mode if HTTP 400 occurs (schema format unsupported by endpoint)
        if resp.status_code == 400:
            logger.warning(
                f"{type(self).__name__} returned HTTP 400 with json_schema mode. Attempting fallback to json_object mode."
            )
            fallback_instruction = (
                "\n\nCRITICAL INSTRUCTION: You must respond ONLY with a JSON object conforming to the "
                "AIAnalysisResult schema with these exact keys:\n"
                "- priority (string: 'Critical', 'High', 'Medium', or 'Low')\n"
                "- simple_explanation (string)\n"
                "- why_it_matters (string)\n"
                "- severity_explanation (string)\n"
                "- risk_factors (array of strings)\n"
                "- potential_business_impact (array of strings)\n"
                "- recommendation (array of strings)\n"
                "- remediation (object with: immediate_mitigation: [string], permanent_remediation: [string], validation: [string])\n"
                "- recommended_controls (array of objects with: name: string, reason: string)\n"
                "- confidence (float between 0.0 and 1.0)\n"
                "- human_review_required (boolean)\n"
                "- human_review_reasons (array of strings)\n"
                f"- model_name (string: '{self.model_name}')\n\n"
                "Do NOT echo the input context keys. Output ONLY the analysis JSON structure above."
            )
            payload["response_format"] = {"type": "json_object"}
            payload["messages"] = [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": prompt + fallback_instruction},
            ]
            try:
                resp = requests.post(
                    self.endpoint,
                    headers=headers,
                    json=payload,
                    timeout=self.timeout_seconds,
                )
            except requests.Timeout as err:
                raise AIProviderTransientError(
                    f"{type(self).__name__} request timed out on json_object fallback after {self.timeout_seconds}s"
                ) from err
            except requests.RequestException as err:
                raise AIProviderTransientError(
                    f"{type(self).__name__} network error on json_object fallback: {_sanitize_compact(str(err))}"
                ) from err

        if resp.status_code != 200:
            err_body = _sanitize_compact(resp.text)
            if resp.status_code in (401, 403):
                raise AIProviderFatalError(
                    f"{type(self).__name__} authentication/authorization error (HTTP {resp.status_code}): {err_body}"
                )
            elif resp.status_code == 429:
                raise AIProviderTransientError(
                    f"{type(self).__name__} rate limit exceeded (HTTP 429): {err_body}"
                )
            elif resp.status_code in (500, 502, 503, 504):
                raise AIProviderTransientError(
                    f"{type(self).__name__} service error (HTTP {resp.status_code}): {err_body}"
                )
            else:
                raise AIProviderTransientError(
                    f"{type(self).__name__} HTTP error {resp.status_code}: {err_body}"
                )

        try:
            data = resp.json()
            raw_content = data["choices"][0]["message"]["content"]
            if isinstance(raw_content, str):
                stripped = raw_content.strip()
                if stripped.startswith("```json"):
                    stripped = stripped[7:]
                elif stripped.startswith("```"):
                    stripped = stripped[3:]
                if stripped.endswith("```"):
                    stripped = stripped[:-3]
                parsed_json = json.loads(stripped.strip())
            elif isinstance(raw_content, dict):
                parsed_json = raw_content
            else:
                raise ValueError(f"Unexpected content type: {type(raw_content)}")
        except (KeyError, IndexError, json.JSONDecodeError, TypeError, ValueError) as err:
            raise AIProviderTransientError(
                f"Failed to parse {type(self).__name__} response JSON: {_sanitize_compact(str(err))}"
            ) from err

        parsed_json["model_name"] = self.model_name
        try:
            result = AIAnalysisResult(**parsed_json)
        except Exception as val_err:
            raise AIProviderTransientError(
                f"{type(self).__name__} schema validation error: {_sanitize_compact(str(val_err))}"
            ) from val_err

        return validate_and_sanitize_result(result, context)


class OpenAIProvider(_OpenAICompatibleProvider):
    """Production-grade OpenAI provider with JSON Schema structured output and typed error classification."""

    DEFAULT_MODEL = "gpt-4o-mini"
    DEFAULT_TIMEOUT_SECONDS = 7
    MODEL_ENV = "OPENAI_MODEL"
    KEY_ENV = "OPENAI_API_KEY"
    DEFAULT_ENDPOINT = "https://api.openai.com/v1/chat/completions"
    ENDPOINT_ENV = "OPENAI_ENDPOINT"
    TIMEOUT_ENV = "OPENAI_TIMEOUT_SECONDS"


class GroqProvider(_OpenAICompatibleProvider):
    """Production-grade Groq provider using OpenAI-compatible endpoints and structured outputs."""

    DEFAULT_MODEL = "openai/gpt-oss-120b"
    DEFAULT_TIMEOUT_SECONDS = 5
    MODEL_ENV = "GROQ_MODEL"
    KEY_ENV = "GROQ_API_KEY"
    DEFAULT_ENDPOINT = "https://api.groq.com/openai/v1/chat/completions"
    ENDPOINT_ENV = "GROQ_ENDPOINT"
    TIMEOUT_ENV = "GROQ_TIMEOUT_SECONDS"

    @property
    def model_name(self) -> str:
        return f"{self._api_model} (via groq)"


# ---------------------------------------------------------------------------
# Multi-LLM Provider Failover Orchestrator (ProviderChain)
# ---------------------------------------------------------------------------

class ProviderChain(AIProvider):
    """Sequential multi-provider failover orchestrator.

    - Attempts providers in order; on any exception, logs the attempt and advances.
    - RuleAssistedAIProvider is ALWAYS the final item (guaranteed by factory).
    - Never raises AIProviderError to the caller when RuleAssisted is present.
    - Implements AIProvider — injectable into analyze_risk(provider=chain) for tests.
    """

    def __init__(self, providers: List[AIProvider]):
        if not providers:
            raise ValueError("ProviderChain requires at least one provider.")
        self._providers = list(providers)
        self._attempts: List[ProviderAttempt] = []

    @property
    def attempts(self) -> List[ProviderAttempt]:
        """Audit records of all provider attempts during the most recent analysis."""
        return list(self._attempts)

    @property
    def model_name(self) -> str:
        """Identifier of the primary model in the chain."""
        if self._providers:
            return getattr(self._providers[0], "model_name", "chain")
        return "chain"

    def analyze_finding(self, context: NormalizedSecurityContext) -> AIAnalysisResult:
        self._attempts = []
        for provider in self._providers:
            provider_label = getattr(provider, "provider_name", type(provider).__name__)
            model_label = getattr(
                provider,
                "model_name",
                getattr(provider, "MODEL_NAME", provider_label),
            )
            try:
                result = provider.analyze_finding(context)
                self._attempts.append(
                    ProviderAttempt(
                        provider_name=provider_label,
                        model_name=model_label,
                        succeeded=True,
                        error_type=None,
                        error_message=None,
                    )
                )
                if any(not a.succeeded for a in self._attempts):
                    self._annotate_failover(result)
                return result
            except Exception as err:
                err_msg = _sanitize_compact(str(err))
                logger.warning(
                    f"ProviderChain: {provider_label} failed ({type(err).__name__}): {err_msg}"
                )
                self._attempts.append(
                    ProviderAttempt(
                        provider_name=provider_label,
                        model_name=model_label,
                        succeeded=False,
                        error_type=type(err).__name__,
                        error_message=err_msg,
                    )
                )
                continue

        # Unreachable if chain is built correctly (RuleAssisted always last)
        raise AIProviderError("ProviderChain exhausted all providers without success.")

    def _annotate_failover(self, result: AIAnalysisResult) -> None:
        """Inject compact audit trail into result when failover occurred."""
        failed_names = ", ".join(a.provider_name for a in self._attempts if not a.succeeded)
        result.human_review_required = True
        if result.human_review_reasons is None:
            result.human_review_reasons = []
        failover_note = (
            f"Chain failover: {failed_names[:80]} unavailable; result from {result.model_name[:40]}."
        )
        if failover_note not in result.human_review_reasons:
            result.human_review_reasons.append(failover_note)
        result.model_name = f"{result.model_name} (chain-failover: {failed_names})"


# ---------------------------------------------------------------------------
# Factory Function & Helpers
# ---------------------------------------------------------------------------

def _build_provider_chain() -> ProviderChain:
    """Build ProviderChain from AI_PROVIDER_CHAIN env var.

    RuleAssistedAIProvider is ALWAYS appended as the guaranteed final fallback.
    """
    chain_spec = os.getenv("AI_PROVIDER_CHAIN", "gemini,openai,groq").strip().lower()
    provider_names = [p.strip() for p in chain_spec.split(",") if p.strip()]

    providers: List[AIProvider] = []
    for name in provider_names:
        if name in ("gemini", "google"):
            # CRITICAL: fallback_enabled=False when inside chain to let failover advance
            providers.append(GeminiAIProvider(fallback_enabled=False))
        elif name in ("openai", "openai-native"):
            providers.append(OpenAIProvider())
        elif name == "groq":
            providers.append(GroqProvider())
        elif name in ("local", "rule", "rule-assisted"):
            pass  # Appended unconditionally below
        else:
            logger.warning(f"Unknown provider '{name}' in AI_PROVIDER_CHAIN — skipping.")

    # Unconditionally append guaranteed deterministic fallback
    providers.append(RuleAssistedAIProvider())
    return ProviderChain(providers)


def get_ai_provider() -> AIProvider:
    """Factory function resolving configured AI provider via environment variables.

    Defaults to ProviderChain with sequential failover:
    Gemini -> OpenAI -> Groq -> RuleAssisted.

    Explicit options:
      AI_PROVIDER=chain         -> ProviderChain (default)
      AI_PROVIDER=gemini        -> GeminiAIProvider (Phase 4A standalone behavior)
      AI_PROVIDER=local         -> RuleAssistedAIProvider
      AI_PROVIDER=openai        -> ExternalLLMProvider (Phase 4A backward-compatible)
      AI_PROVIDER=openai-native -> OpenAIProvider (Phase 4C production provider)
      AI_PROVIDER=groq          -> GroqProvider
    """
    ensure_env_loaded()
    provider_type = os.getenv("AI_PROVIDER", "chain").strip().lower()

    if provider_type in ["gemini", "google"]:
        fallback_enabled = os.getenv("AI_FALLBACK_TO_LOCAL", "true").strip().lower() in ("true", "1", "yes")
        return GeminiAIProvider(fallback_enabled=fallback_enabled)

    if provider_type in ["local", "rule", "rule-assisted"]:
        return RuleAssistedAIProvider()

    if provider_type in ["openai", "external"]:
        return ExternalLLMProvider()

    if provider_type in ["openai-native"]:
        return OpenAIProvider()

    if provider_type in ["groq"]:
        return GroqProvider()

    if provider_type in ["chain"]:
        return _build_provider_chain()

    # Default fallback is chain
    return _build_provider_chain()
