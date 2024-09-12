from pydash import get

from power_platform_security_assessment.base_classes import Application
from power_platform_security_assessment.security_features.bypass_consent.bypass_concent_textual_report import BypassConsentTextualReport
from power_platform_security_assessment.security_features.bypass_consent.model import BypassConsentResult


class BypassConsentAnalyzer:
    def __init__(self, applications: list[Application]):
        self._applications = applications
        self._bypass_consent_textual_report_generator = BypassConsentTextualReport()

    def analyze(self) -> BypassConsentResult:
        bypass_consent_apps = [
            app for app in self._applications
            if app.properties.bypassConsent
               and get(app, 'properties.embeddedApp.type') == 'SharepointFormApp'
        ]

        textual_report = self._bypass_consent_textual_report_generator.generate_textual_report(bypass_consent_apps)

        return BypassConsentResult(
            bypass_consent_apps=bypass_consent_apps,
            textual_report=textual_report,
        )
