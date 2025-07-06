from pydantic import BaseModel

from power_platform_security_assessment.base_classes import Application


class BypassConsentResult(BaseModel):
    bypass_consent_apps: list[Application]
    textual_report: str
