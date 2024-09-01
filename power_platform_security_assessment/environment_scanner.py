import concurrent.futures

from power_platform_security_assessment.base_classes import (
    Environment, User, Application, CloudFlow, ConnectorWithConnections, DesktopFlow, ModelDrivenApp
)
from power_platform_security_assessment.fetchers.applications_fetcher import ApplicationsFetcher
from power_platform_security_assessment.fetchers.cloud_flows_fetcher import CloudFlowsFetcher
from power_platform_security_assessment.fetchers.connections_fetcher import ConnectionsFetcher
from power_platform_security_assessment.fetchers.desktop_flows_fetcher import DesktopFlowsFetcher
from power_platform_security_assessment.fetchers.model_driven_apps_fetcher import ModelDrivenAppsFetcher
from power_platform_security_assessment.fetchers.users_fetcher import UsersFetcher
from power_platform_security_assessment.token_manager import TokenManager


class EnvironmentScanner:
    def __init__(self, environment: Environment, token_manager: TokenManager):
        self._environment = environment
        self._env_id = environment.id.split('/')[-1]
        self._token_manager = token_manager

    def _fetch_applications(self) -> list[Application]:
        app_fetcher = ApplicationsFetcher(
            env_id=self._env_id,
            token_manager=self._token_manager,
        )

        return app_fetcher.fetch_applications()

    def _fetch_cloud_flows(self) -> list[CloudFlow]:
        cloud_flow_fetcher = CloudFlowsFetcher(
            env_id=self._env_id,
            token_manager=self._token_manager,
        )

        return cloud_flow_fetcher.fetch_cloud_flows()

    def _fetch_desktop_flows(self) -> list[DesktopFlow]:
        if not self._environment.properties.linkedEnvironmentMetadata:
            return []

        desktop_flow_fetcher = DesktopFlowsFetcher(
            instance_api_url=self._environment.properties.linkedEnvironmentMetadata.instanceApiUrl,
            env_id=self._env_id,
            token_manager=self._token_manager,
        )

        return desktop_flow_fetcher.fetch_desktop_flows()

    def _fetch_model_driven_apps(self) -> list[ModelDrivenApp]:
        if not self._environment.properties.linkedEnvironmentMetadata:
            return []

        model_driven_apps_fetcher = ModelDrivenAppsFetcher(
            instance_api_url=self._environment.properties.linkedEnvironmentMetadata.instanceApiUrl,
            env_id=self._env_id,
            token_manager=self._token_manager,
        )

        return model_driven_apps_fetcher.fetch_model_driven_apps()

    def _fetch_connections(self) -> list[ConnectorWithConnections]:
        connections_fetcher = ConnectionsFetcher(
            env_id=self._env_id,
            token_manager=self._token_manager,
        )

        return connections_fetcher.fetch_connections()

    def _fetch_users(self) -> list[User]:
        if not self._environment.properties.linkedEnvironmentMetadata:
            return []

        users_fetcher = UsersFetcher(
            instance_api_url=self._environment.properties.linkedEnvironmentMetadata.instanceApiUrl,
            env_id=self._env_id,
            token_manager=self._token_manager,
        )

        return users_fetcher.fetch_users()

    def scan_environment(self):
        with concurrent.futures.ThreadPoolExecutor() as executor:
            results = {'environment': self._environment.properties.displayName}
            futures = {
                executor.submit(self._fetch_applications): 'applications',
                executor.submit(self._fetch_cloud_flows): 'cloud_flows',
                executor.submit(self._fetch_desktop_flows): 'desktop_flows',
                executor.submit(self._fetch_model_driven_apps): 'model_driven_apps',
                executor.submit(self._fetch_connections): 'connections',
                executor.submit(self._fetch_users): 'users',
            }

            for future in concurrent.futures.as_completed(futures):
                data_type = futures[future]
                try:
                    results[data_type] = future.result()
                except Exception as e:
                    # todo: handle exceptions properly
                    results[data_type] = None
                    print(f"An error occurred while fetching {data_type} for environment {self._environment.properties.displayName}. {e}")

            return results
