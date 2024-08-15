import concurrent.futures

import msal

from power_platform_security_assessment.base_classes import Environment
from power_platform_security_assessment.consts import Requests, ResponseKeys
from power_platform_security_assessment.environment_scanner import EnvironmentScanner
from power_platform_security_assessment.environments_fetcher import EnvironmentsFetcher


class SecurityAssessmentTool:
    def __init__(self, assessment_tool_name, assessment_tool_version):
        self.assessment_tool_name = assessment_tool_name
        self.assessment_tool_version = assessment_tool_version
        self._access_token = None
        self._refresh_token = None
        self._client_id = None

    def _create_token(self):
        app = msal.PublicClientApplication('9cee029c-6210-4654-90bb-17e6e9d36617', authority=Requests.AUTHORITY)
        result = app.acquire_token_interactive(scopes=Requests.SCOPE)

        if ResponseKeys.ACCESS_TOKEN in result:
            self._access_token = result[ResponseKeys.ACCESS_TOKEN]
            self._refresh_token = result.get("refresh_token")
            self._client_id = result.get("id_token_claims").get("aud")
        else:
            raise Exception("Failed to acquire token: %s" % result.get("error_description"))

    def _scan_environment(self, environment: Environment):
        env_scanner = EnvironmentScanner(
            environment=environment,
            refresh_token=self._refresh_token,
            client_id=self._client_id,
        )
        return env_scanner.scan_environment()

    def run_security_assessment(self):
        self._create_token()
        environments = EnvironmentsFetcher().fetch_environments(self._access_token)

        print(
            f'{"environment name":<44} {"applications":<4}')
        with concurrent.futures.ThreadPoolExecutor() as executor:
            futures = [executor.submit(self._scan_environment, environment) for environment in environments]
            for future in concurrent.futures.as_completed(futures):
                try:
                    environment_results = future.result()
                    print(
                        f'{environment_results["environment"]:<44} {environment_results["applications"]:<4}')
                except Exception as e:
                    print(f"An error occurred during environment scanning: {e}")


def main():
    security_assessment_tool = SecurityAssessmentTool("Security Assessment Tool", "1.0")
    security_assessment_tool.run_security_assessment()


if __name__ == '__main__':
    main()
