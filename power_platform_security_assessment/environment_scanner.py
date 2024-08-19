import concurrent.futures

from power_platform_security_assessment.applications_fetcher import ApplicationsFetcher
from power_platform_security_assessment.base_classes import Environment
from power_platform_security_assessment.cloud_flows_fetcher import CloudFlowsFetcher
from power_platform_security_assessment.desktop_flows_fetcher import DesktopFlowsFetcher
from power_platform_security_assessment.token_manager import TokenManager


class EnvironmentScanner:
    def __init__(self, environment: Environment, token_manager: TokenManager):
        self._environment = environment
        self._env_id = environment.id.split('/')[-1]
        self._token_manager = token_manager

    def _fetch_applications(self) -> int:
        app_fetcher = ApplicationsFetcher(
            env_id=self._env_id,
            token_manager=self._token_manager,
        )

        return app_fetcher.fetch_application_count()

    def _fetch_cloud_flows(self) -> int:
        cloud_flow_fetcher = CloudFlowsFetcher(
            env_id=self._env_id,
            token_manager=self._token_manager,
        )

        return cloud_flow_fetcher.fetch_cloud_flows_count()

    def _fetch_desktop_flows(self) -> int:
        if not self._environment.properties.linkedEnvironmentMetadata:
            return 0

        desktop_flow_fetcher = DesktopFlowsFetcher(
            instance_api_url=self._environment.properties.linkedEnvironmentMetadata.instanceApiUrl,
            env_id=self._env_id,
            token_manager=self._token_manager,
        )

        return desktop_flow_fetcher.fetch_desktop_flows_count()

    def _fetch_model_driven_apps(self):
        pass

    def _fetch_connections(self):
        pass
        ...

    def _fetch_users(self):
        pass

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
                    print(f"An error occurred while fetching {data_type}: {e}")

            return results
