import concurrent.futures

import msal

from power_platform_security_assessment.base_classes import Environment, User, Connector, ConnectionExtended
from power_platform_security_assessment.consts import Requests, ResponseKeys
from power_platform_security_assessment.environment_scanner import EnvironmentScanner
from power_platform_security_assessment.fetchers.environments_fetcher import EnvironmentsFetcher
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
        print(
            f'{"Environment":<44} {"Applications":<15} {"Cloud Flows":<15} {"Desktop Flows":<15} {"Model-Driven Apps":<18} {"Total":<15}')

        for environment_results in environments_results:
            environment_name = environment_results["environment"]
            applications_count = len(environment_results["applications"])
            cloud_flows_count = len(environment_results["cloud_flows"])
            desktop_flows_count = environment_results["desktop_flows"]
            model_driven_apps_count = environment_results["model_driven_apps"]
            total = applications_count + cloud_flows_count + desktop_flows_count + model_driven_apps_count
            print(
                f'{environment_name:<44} {applications_count:<15} {cloud_flows_count:<15} {desktop_flows_count:<15} {model_driven_apps_count:<18} {total:<15}')

        print()

    @staticmethod
    def _handle_environment_users(environments_results) -> list[User]:
        users_list: list[User] = []
        for environment_results in environments_results:
            environment_users: list[User] = environment_results["users"]
            existing_user_ids = {u.azureactivedirectoryobjectid for u in users_list}
            users_list.extend(
                user for user in environment_users
                if user.azureactivedirectoryobjectid and user.azureactivedirectoryobjectid not in existing_user_ids
            )

        return users_list

    @staticmethod
    def _display_users(users_list):
        print(f'{"Total Users":<18}')
        print(f'{len(users_list):<18}')

        print(f'{"Internal Users":<18} {"Guest Users":<18}')
        guest_users = [user for user in users_list if user.domainname and user.domainname.find('#EXT#') != -1]
        internal_users = [user for user in users_list if user not in guest_users]
        print(f'{len(internal_users):<18} {len(guest_users):<18}')

        print(f'{"Azure state 0":<18} {"Azure state 1":<18} {"Azure state 2":<18}')
        azure_state_0 = [user for user in users_list if user.azurestate == 0]
        azure_state_1 = [user for user in users_list if user.azurestate == 1]
        azure_state_2 = [user for user in users_list if user.azurestate == 2]
        print(f'{len(azure_state_0):<18} {len(azure_state_1):<18} {len(azure_state_2):<18}')
        print()

    @staticmethod
    def _print_connections(environments_results):
        connector_connections: dict[Connector, int] = {}
        for environment_results in environments_results:
            connections: list[ConnectionExtended] = environment_results["connections"]
            for connection in connections:
                connector_connections[connection.connector] = connector_connections.get(connection.connector, 0) + 1

        sorted_connector_connections = sorted(connector_connections.items(), key=lambda x: x[1], reverse=True)
        print(f'{"Connector":<22} {"Publisher":<22} {"Number of Connections":<22}')
        for connector, connections_count in sorted_connector_connections[:3]: # take top 3
            print(
                f'{connector.name:<22} {connector.properties.metadata.source:<22} {connections_count:<22}')
        print()

    def _handle_results(self, environments_results):
        self._display_environment_results(environments_results)
        users_list = self._handle_environment_users(environments_results)
        self._display_users(users_list)
        self._print_connections(environments_results)

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

        self._handle_results(environments_results)


def main():
    security_assessment_tool = SecurityAssessmentTool("Security Assessment Tool", "1.0")
    security_assessment_tool.run_security_assessment()


if __name__ == '__main__':
    main()
