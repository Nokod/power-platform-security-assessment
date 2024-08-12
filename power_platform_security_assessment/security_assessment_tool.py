import msal
import requests

from power_platform_security_assessment.consts import Requests, ResponseKeys
from power_platform_security_assessment.base_classes import Environment


class SecurityAssessmentTool:
    def __init__(self, assessment_tool_name, assessment_tool_version):
        self.assessment_tool_name = assessment_tool_name
        self.assessment_tool_version = assessment_tool_version
        self._access_token = None
        self._refresh_token = None

    def _create_token(self):
        """
        Acquires an access token using the Microsoft Authentication Library (MSAL).
        """
        app = msal.PublicClientApplication('9cee029c-6210-4654-90bb-17e6e9d36617',
                                           authority=Requests.AUTHORITY)
        result = app.acquire_token_interactive(scopes=Requests.SCOPE)

        if ResponseKeys.ACCESS_TOKEN in result:
            self._access_token = result[ResponseKeys.ACCESS_TOKEN]
            self._refresh_token = result.get("refresh_token")
        else:
            raise Exception("Failed to acquire token: %s" % result.get("error_description"))

    def _fetch_environments(self):
        res = requests.get(
            'https://api.bap.microsoft.com/providers/Microsoft.BusinessAppPlatform/scopes/admin/environments?api-version=2021-04-01',
            headers={'Authorization': f'Bearer {self._access_token}'})
        return [Environment(**env) for env in res.json().get('value', [])]

    def run_security_assessment(self):
        self._create_token()
        environments = self._fetch_environments()
        for environment in environments:
            print(f'Handling environment: {environment.properties.displayName}')


def main():
    security_assessment_tool = SecurityAssessmentTool("Security Assessment Tool", "1.0")
    security_assessment_tool.run_security_assessment()


if __name__ == '__main__':
    main()
