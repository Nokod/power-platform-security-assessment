import concurrent.futures

import msal
from pydash import flatten_deep, values

from power_platform_security_assessment.base_classes import (
    Environment, User, ConnectorWithConnections, Application, ResourceData, CloudFlow, DesktopFlow, ModelDrivenApp
)
from power_platform_security_assessment.consts import Requests, ResponseKeys
from power_platform_security_assessment.environment_scanner import EnvironmentScanner
from power_platform_security_assessment.fetchers.environments_fetcher import EnvironmentsFetcher
from power_platform_security_assessment.security_features.app_developers.app_developer_analyzer import AppDeveloperAnalyzer
from power_platform_security_assessment.security_features.bypass_consent.bypass_consent_analyzer import BypassConsentAnalyzer
from power_platform_security_assessment.security_features.connectors.connectors_analyzer import ConnectorsAnalyzer
from power_platform_security_assessment.token_manager import TokenManager


class SecurityAssessmentTool:
    def __init__(self, assessment_tool_name, assessment_tool_version):
        self.assessment_tool_name = assessment_tool_name
        self.assessment_tool_version = assessment_tool_version
        self._access_token = None
        self._refresh_token = None
        self._client_id = None

    def _create_token(self):
        app = msal.PublicClientApplication('9cee029c-6210-4654-90bb-17e6e9d36617', authority=Requests.AUTHORITY)
        result = app.acquire_token_interactive(scopes=Requests.ENVIRONMENTS_SCOPE)

        if ResponseKeys.ACCESS_TOKEN in result:
            self._access_token = result[ResponseKeys.ACCESS_TOKEN]
            self._refresh_token = result.get("refresh_token")
            self._client_id = result.get("id_token_claims").get("aud")
        else:
            raise Exception("Failed to acquire token: %s" % result.get("error_description"))

    @staticmethod
    def _scan_environment(environment: Environment, token_manager: TokenManager):
        env_scanner = EnvironmentScanner(
            environment=environment,
            token_manager=token_manager,
        )
        return env_scanner.scan_environment()

    @staticmethod
    def _display_environment_results(environments_results):
        print(f'{"Environment":<44} {"Applications":<15} {"Cloud Flows":<15} {"Desktop Flows":<15} {"Model-Driven Apps":<18} {"Total":<15}')

        results: list[tuple[str, ResourceData, ResourceData, ResourceData, ResourceData, int]] = []
        for environment_results in environments_results:
            environment_name: str = environment_results["environment"]

            applications_result: ResourceData[Application] = environment_results["applications"]
            cloud_flows_result: ResourceData[CloudFlow] = environment_results["cloud_flows"]
            desktop_flows_result: ResourceData[DesktopFlow] = environment_results["desktop_flows"]
            model_driven_apps_result: ResourceData[ModelDrivenApp] = environment_results["model_driven_apps"]

            results.append((
                environment_name,
                applications_result,
                cloud_flows_result,
                desktop_flows_result,
                model_driven_apps_result,
                applications_result.count + cloud_flows_result.count + desktop_flows_result.count + model_driven_apps_result.count
            ))

        # sort by total
        results = sorted(results, key=lambda x: x[5], reverse=True)

        # display results
        for result in results:
            total_has_plus = any(
                not result[i].all_resources_fetched
                for i in range(1, 5)
            )
            print(
                f'{result[0]:<44} '
                f'{str(result[1].count) + ("+" if not result[1].all_resources_fetched else ""):<15} '
                f'{str(result[2].count) + ("+" if not result[2].all_resources_fetched else ""):<15} '
                f'{str(result[3].count) + ("+" if not result[3].all_resources_fetched else ""):<15} '
                f'{str(result[4].count) + ("+" if not result[4].all_resources_fetched else ""):<18} '
                f'{str(result[5]) + ("+" if total_has_plus else ""):<15} '
            )

        print()

    @staticmethod
    def _handle_environment_users(environments_results) -> list[User]:
        users_list: list[User] = []
        for environment_results in environments_results:
            environment_users: list[User] = environment_results["users"].value
            existing_user_ids = {u.azureactivedirectoryobjectid for u in users_list}
            users_list.extend(
                user for user in environment_users
                if user.azureactivedirectoryobjectid and user.azureactivedirectoryobjectid not in existing_user_ids
            )

        return users_list

    @staticmethod
    def _handle_connector_connections(environments_results):
        # Dictionary to map connector names to their respective ConnectorWithConnections objects
        connector_mapping: dict[str, ConnectorWithConnections] = {}

        for environment_results in environments_results:
            for connector_with_connections in environment_results["connections"].value:
                connector_name = connector_with_connections.connector.name
                if connector_name in connector_mapping:
                    connector_mapping[connector_name].connections.extend(connector_with_connections.connections)
                else:
                    connector_mapping[connector_name] = connector_with_connections

        # Convert the dictionary back to a list
        all_connector_connections = values(connector_mapping)

        # Return connectors sorted by the number of connections
        return sorted(all_connector_connections, key=lambda x: len(x.connections), reverse=True)

    @staticmethod
    def _display_users(users_list):
        print(f'{"Total Users":<22}')
        print(f'{len(users_list):<22}')

        print(f'{"Internal Users":<22} {"Guest Users":<22}')
        guest_users = [user for user in users_list if user.domainname and user.domainname.find('#EXT#') != -1]
        internal_users = [user for user in users_list if user not in guest_users]
        print(f'{len(internal_users):<22} {len(guest_users):<22}')

        print(f'{"Active (0)":<22} {"AD soft delete (1)":<22} {"AD hard delete (2)":<22}')
        azure_state_0 = [user for user in users_list if user.azurestate == 0]
        azure_state_1 = [user for user in users_list if user.azurestate == 1]
        azure_state_2 = [user for user in users_list if user.azurestate == 2]
        print(f'{len(azure_state_0):<22} {len(azure_state_1):<22} {len(azure_state_2):<22}')
        print()

    @staticmethod
    def _display_connections(all_connector_connections: list[ConnectorWithConnections]):
        print(f'{"Connector":<22} {"Publisher":<22} {"Number of Connections":<22}')
        for connector_with_connections in all_connector_connections[:3]:
            connector = connector_with_connections.connector
            connections_count = len(connector_with_connections.connections)
            print(f'{connector.name:<22} {connector.properties.publisher:<22} {connections_count:<22}')

        print()

    @staticmethod
    def _display_app_developers(all_applications, all_cloud_flows, users_list, environments):
        app_developer_analyzer = AppDeveloperAnalyzer(all_applications, all_cloud_flows, users_list, environments)
        app_developers_result = app_developer_analyzer.analyze()
        print(app_developers_result.textual_report)

    @staticmethod
    def _display_connector_issues(all_connector_connections: list[ConnectorWithConnections]):
        connectors_analyzer = ConnectorsAnalyzer(all_connector_connections)
        result = connectors_analyzer.analyze()
        print(result.textual_report)

    @staticmethod
    def _display_bypass_consent(all_applications: list[Application]):
        bypass_consent_analyzer = BypassConsentAnalyzer(all_applications)
        bypass_consent_result = bypass_consent_analyzer.analyze()
        print(bypass_consent_result.textual_report)

    def _handle_results(self, environments_results: list, environments: list[Environment]):
        all_users_list = self._handle_environment_users(environments_results)
        all_connector_connections = self._handle_connector_connections(environments_results)
        all_applications = flatten_deep([env_results["applications"].value for env_results in environments_results])
        all_cloud_flows = flatten_deep([env_results["cloud_flows"].value for env_results in environments_results])

        self._display_environment_results(environments_results)
        self._display_users(all_users_list)
        self._display_connections(all_connector_connections)

        self._display_app_developers(all_applications, all_cloud_flows, all_users_list, environments)
        self._display_connector_issues(all_connector_connections)
        self._display_bypass_consent(all_applications)

    def run_security_assessment(self):
        self._create_token()
        environments = EnvironmentsFetcher().fetch_environments(self._access_token)
        token_manager = TokenManager(self._client_id, self._refresh_token)
        environments_results = []

        with concurrent.futures.ThreadPoolExecutor() as executor:
            futures = [executor.submit(self._scan_environment, environment, token_manager) for environment in environments]
            for future in concurrent.futures.as_completed(futures):
                try:
                    environments_results.append(future.result())
                except Exception as e:
                    print(f"An error occurred during environment scanning: {e}")

        self._handle_results(environments_results, environments)


def main():
    security_assessment_tool = SecurityAssessmentTool("Security Assessment Tool", "1.0")
    security_assessment_tool.run_security_assessment()


if __name__ == '__main__':
    main()
