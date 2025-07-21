import concurrent.futures

from power_platform_security_assessment.base_classes import (
    Environment, User, Application, CloudFlow, ConnectorWithConnections, DesktopFlow, ModelDrivenApp, ResourceData
)
from power_platform_security_assessment.consts import ComponentType
from power_platform_security_assessment.fetchers.applications_fetcher import ApplicationsFetcher
from power_platform_security_assessment.fetchers.cloud_flows_fetcher import CloudFlowsFetcher
from power_platform_security_assessment.fetchers.connections_fetcher import ConnectionsFetcher
from power_platform_security_assessment.fetchers.desktop_flows_fetcher import DesktopFlowsFetcher
from power_platform_security_assessment.fetchers.model_driven_apps_fetcher import ModelDrivenAppsFetcher
from power_platform_security_assessment.fetchers.users_fetcher import UsersFetcher
from power_platform_security_assessment.token_manager import TokenManager
from power_platform_security_assessment.logger import Logger


class EnvironmentScanner:
    def __init__(self, environment: Environment, token_manager: TokenManager, logger: Logger):
        self._environment = environment
        self._env_id = environment.id.split('/')[-1]
        self._token_manager = token_manager
        self._logger = logger

    def _fetch_applications(self) -> ResourceData[Application]:
        app_fetcher = ApplicationsFetcher(
            env_id=self._env_id,
            token_manager=self._token_manager,
            logger=self._logger,
        )

        return app_fetcher.fetch_resource_data()

    def _fetch_cloud_flows(self) -> ResourceData[CloudFlow]:
        cloud_flow_fetcher = CloudFlowsFetcher(
            env_id=self._env_id,
            token_manager=self._token_manager,
            logger=self._logger,
        )

        return cloud_flow_fetcher.fetch_resource_data()

    def _fetch_desktop_flows(self) -> ResourceData[DesktopFlow]:
        if not self._environment.properties.linkedEnvironmentMetadata:
            return ResourceData()

        desktop_flow_fetcher = DesktopFlowsFetcher(
            instance_api_url=self._environment.properties.linkedEnvironmentMetadata.instanceApiUrl,
            env_id=self._env_id,
            token_manager=self._token_manager,
            logger=self._logger,
        )

        return desktop_flow_fetcher.fetch_resource_data()

    def _fetch_model_driven_apps(self) -> ResourceData[ModelDrivenApp]:
        if not self._environment.properties.linkedEnvironmentMetadata:
            return ResourceData()

        model_driven_apps_fetcher = ModelDrivenAppsFetcher(
            instance_api_url=self._environment.properties.linkedEnvironmentMetadata.instanceApiUrl,
            env_id=self._env_id,
            token_manager=self._token_manager,
            logger=self._logger,
        )

        return model_driven_apps_fetcher.fetch_resource_data()

    def _fetch_connections(self) -> ResourceData[ConnectorWithConnections]:
        connections_fetcher = ConnectionsFetcher(
            env_id=self._env_id,
            token_manager=self._token_manager,
            logger=self._logger,
        )

        return connections_fetcher.fetch_resource_data()

    def _fetch_users(self) -> ResourceData[User]:
        if not self._environment.properties.linkedEnvironmentMetadata:
            return ResourceData()

        users_fetcher = UsersFetcher(
            instance_api_url=self._environment.properties.linkedEnvironmentMetadata.instanceApiUrl,
            env_id=self._env_id,
            token_manager=self._token_manager,
            logger=self._logger,
        )

        return users_fetcher.fetch_resource_data()

    def scan_environment(self):
        self._logger.log(
            f"Starting scan for environment: {self._environment.properties.displayName}",
            log_level="debug",
        )

        with concurrent.futures.ThreadPoolExecutor() as executor:
            results = {ComponentType.ENVIRONMENT: self._environment, 'error': None}
            futures = {
                executor.submit(self._fetch_applications): ComponentType.APPLICATIONS,
                executor.submit(self._fetch_cloud_flows): ComponentType.CLOUD_FLOWS,
                executor.submit(self._fetch_desktop_flows): ComponentType.DESKTOP_FLOWS,
                executor.submit(self._fetch_model_driven_apps): ComponentType.MODEL_DRIVEN_APPS,
                executor.submit(self._fetch_connections): ComponentType.CONNECTIONS,
                executor.submit(self._fetch_users): ComponentType.USERS,
            }

            for future in concurrent.futures.as_completed(futures):
                data_type: ComponentType = futures[future]
                try:
                    results[data_type] = future.result()
                    self._logger.log(
                        f"Successfully fetched {data_type} for environment: {self._environment.properties.displayName}",
                        log_level="debug",
                    )
                except Exception as e:
                    results[data_type] = None
                    results['error'] = e
                    self._logger.log(
                        f"Failed to fetch {data_type} for environment: {self._environment.properties.displayName}. Error: {str(e)}",
                        log_level="error",
                    )

            if not results['error']:
                self._logger.log(
                    f"Successfully scanned environment: {self._environment.properties.displayName}",
                    log_level="debug",
                )
            else:
                self._logger.log(
                    f"Environment scan failed for: {self._environment.properties.displayName}, error: {results['error']}",
                    log_level="error",
                )

            return results
