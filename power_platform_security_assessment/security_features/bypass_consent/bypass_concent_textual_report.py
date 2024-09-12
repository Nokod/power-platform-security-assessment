from power_platform_security_assessment.base_classes import Application


class BypassConsentTextualReport:

    @staticmethod
    def generate_textual_report(bypass_consent_apps: list[Application]) -> str:
        verb = "is" if len(bypass_consent_apps) == 1 else "are"
        has_or_have = "has" if len(bypass_consent_apps) == 1 else "have"

        textual_report = (
            f'There {verb} <b>{len(bypass_consent_apps)}</b> application{"" if len(bypass_consent_apps) == 1 else "s"} '
            f'that {has_or_have} the <b>"Bypass Consent"</b> feature enabled.<br>'
            f'This feature allows the application owner to access or change information on behalf of '
            f'the application users, without their consent.'
        )

        return textual_report
