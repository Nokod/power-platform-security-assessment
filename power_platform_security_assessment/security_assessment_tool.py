import concurrent.futures
from collections import Counter

import msal
from alive_progress import alive_bar
from pydash import flatten_deep, values

from power_platform_security_assessment.base_classes import (
    Environment, User, ConnectorWithConnections, Application, ResourceData, CloudFlow, DesktopFlow, ModelDrivenApp
)
from power_platform_security_assessment.consts import Requests, ResponseKeys, ComponentType
from power_platform_security_assessment.environment_scanner import EnvironmentScanner
from power_platform_security_assessment.fetchers.environments_fetcher import EnvironmentsFetcher
from power_platform_security_assessment.report_builder.report_builder import ReportBuilder
from power_platform_security_assessment.security_features.app_developers.app_developer_analyzer import \
    AppDeveloperAnalyzer
from power_platform_security_assessment.security_features.bypass_consent.bypass_consent_analyzer import \
    BypassConsentAnalyzer
from power_platform_security_assessment.security_features.connectors.connectors_analyzer import ConnectorsAnalyzer
from power_platform_security_assessment.token_manager import TokenManager


class SecurityAssessmentTool:
    def __init__(self):
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
    def _display_environment_results(environments_results, failed_environments):
        print(
            f'{"Environment":<44} {"Canvas Apps":<15} {"Cloud Flows":<15} {"Desktop Flows":<15} {"Model-Driven Apps":<18} {"Total":<15}')

        results: list[tuple[str, ResourceData, ResourceData, ResourceData, ResourceData, int]] = []
        for environment_results in environments_results:
            environment: Environment = environment_results[ComponentType.ENVIRONMENT]

            applications_result: ResourceData[Application] = environment_results[ComponentType.APPLICATIONS]
            cloud_flows_result: ResourceData[CloudFlow] = environment_results[ComponentType.CLOUD_FLOWS]
            desktop_flows_result: ResourceData[DesktopFlow] = environment_results[ComponentType.DESKTOP_FLOWS]
            model_driven_apps_result: ResourceData[ModelDrivenApp] = environment_results[
                ComponentType.MODEL_DRIVEN_APPS]

            results.append((
                environment.properties.displayName,
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

        if failed_environments:
            print()
            print('Environments failed to scan - Insufficient user permissions:')
            for failed_environment in failed_environments:
                print(f'{failed_environment[ComponentType.ENVIRONMENT].properties.displayName}')

        print()

    @staticmethod
    def _handle_environment_users(environments_results) -> tuple[list[User], bool]:
        all_fetched = True
        users_list: list[User] = []
        for environment_results in environments_results:
            all_fetched = all_fetched and environment_results[ComponentType.USERS].all_resources_fetched
            environment_users: list[User] = environment_results[ComponentType.USERS].value
            existing_user_ids = {u.azureactivedirectoryobjectid for u in users_list}
            users_list.extend(
                user for user in environment_users
                if user.azureactivedirectoryobjectid and user.azureactivedirectoryobjectid not in existing_user_ids
            )

        return users_list, all_fetched

    @staticmethod
    def _handle_connector_connections(environments_results):
        # Dictionary to map connector names to their respective ConnectorWithConnections objects
        connector_mapping: dict[str, ConnectorWithConnections] = {}

        for environment_results in environments_results:
            for connector_with_connections in environment_results[ComponentType.CONNECTIONS].value:
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
    def _display_users(users_list: list[User], all_users_fetched: bool):
        print(f'{"Total Users":<22}')
        print(f'{len(users_list)}' + ("+" if not all_users_fetched else ""))

        user_types = Counter()
        azure_states = Counter()

        for user in users_list:
            user_types['guest' if '#EXT#' in (user.domainname or '') else 'internal'] += 1
            azure_states[user.azurestate] += 1

        print(f'{"Internal Users":<22} {"Guest Users":<22}')
        print(f'{user_types["internal"]:<22} {user_types["guest"]:<22}')

        print(f'{"Active (0)":<22} {"AD Soft Delete (1)":<22} {"AD Hard Delete (2)":<22}')
        print(f'{azure_states[0]:<22} {azure_states[1]:<22} {azure_states[2]:<22}')
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
        return app_developers_result.textual_report

    @staticmethod
    def _display_connector_issues(all_connector_connections: list[ConnectorWithConnections]):
        connectors_analyzer = ConnectorsAnalyzer(all_connector_connections)
        result = connectors_analyzer.analyze()
        return result.textual_report

    @staticmethod
    def _display_bypass_consent(all_applications: list[Application]):
        bypass_consent_analyzer = BypassConsentAnalyzer(all_applications)
        bypass_consent_result = bypass_consent_analyzer.analyze()
        return bypass_consent_result.textual_report

    def _handle_results(self, environments_results: list, failed_environments: list, environments: list[Environment], total_envs: int):
        (all_applications, all_cloud_flows, all_connector_connections, all_desktop_flows, all_model_driven_apps,
         all_users_list, all_users_fetched) = self.fetch_resources(environments_results)

        app_developers_report = self._display_app_developers(all_applications, all_cloud_flows, all_users_list,
                                                             environments)
        connector_issues_report = self._display_connector_issues(all_connector_connections)
        bypass_consent_report = self._display_bypass_consent(all_applications)
        self._display_environment_results(environments_results, failed_environments)
        self._display_users(all_users_list, all_users_fetched)
        self._display_connections(all_connector_connections)

        report_builder = ReportBuilder(all_applications, all_cloud_flows, all_desktop_flows, all_model_driven_apps,
                                       all_users_list, all_connector_connections, environments_results,
                                       failed_environments, environments, total_envs, all_users_fetched)

        report_builder.build_report(app_developers_report, connector_issues_report, bypass_consent_report)

    def fetch_resources(self, environments_results):
        all_users_list, all_users_fetched = self._handle_environment_users(environments_results)
        all_connector_connections = self._handle_connector_connections(environments_results)
        all_applications = flatten_deep(
            [env_results[ComponentType.APPLICATIONS].value for env_results in environments_results])
        all_cloud_flows = flatten_deep(
            [env_results[ComponentType.CLOUD_FLOWS].value for env_results in environments_results])
        all_desktop_flows = flatten_deep(
            [env_results[ComponentType.DESKTOP_FLOWS].value for env_results in environments_results])
        all_model_driven_apps = flatten_deep(
            [env_results[ComponentType.MODEL_DRIVEN_APPS].value for env_results in environments_results])
        return all_applications, all_cloud_flows, all_connector_connections, all_desktop_flows, all_model_driven_apps, all_users_list, all_users_fetched

    def run_security_assessment(self):
        print('Started scanning environments...')
        self._create_token()
        environments, total_envs = EnvironmentsFetcher().fetch_environments(self._access_token)
        token_manager = TokenManager(self._client_id, self._refresh_token)
        environments_results = []
        failed_environments = []

        with alive_bar(len(environments), bar='blocks') as bar:
            with concurrent.futures.ThreadPoolExecutor() as executor:
                futures = [executor.submit(self._scan_environment, environment, token_manager) for environment in
                           environments]
                for future in concurrent.futures.as_completed(futures):
                    try:
                        result = future.result()
                        if not result['error']:
                            environments_results.append(result)
                        else:
                            failed_environments.append(result)
                    except Exception as e:
                        print(f"An error occurred during environment scanning: {e}")
                    finally:
                        bar()

        self._handle_results(environments_results, failed_environments, environments, total_envs)


def main():
    security_assessment_tool = SecurityAssessmentTool()
    security_assessment_tool.run_security_assessment()


if __name__ == '__main__':
    main()
