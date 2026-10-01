from datetime import datetime
from functools import cmp_to_key
from urllib.parse import urlencode

import requests
from dateutil import parser
from dateutil.relativedelta import relativedelta

from power_platform_security_assessment.base_classes import Environment
from power_platform_security_assessment.logger import Logger


class InsufficientPermissionsError(Exception):
    MESSAGE = ('Unable to scan any environment due to missing permissions. '
               'The tool requires a Power Platform administrator (or a global administrator) account.')

    def __init__(self):
        super().__init__(self.MESSAGE)


class EnvironmentsFetcher:
    _MAX_ENVIRONMENTS_TO_SCAN = 10

    def __init__(self, logger: Logger):
        self._logger = logger
        self.environments = []

    def _display_environments(self, environments: list[Environment], total_envs: int):
        max_display_name_length = max([len(env.properties.displayName) for env in environments])
        self._logger.log(f'Total number of environments: {total_envs}')
        self._logger.log()
        self._logger.log(
            f'{"ID":<44} {"Name":<{max_display_name_length}} {"Created By":<20} {"Create Time":<30} {"Last Activity":<30} {"Type":<10}')
        for env in environments:
            created_by = env.properties.createdBy.get('displayName') or 'N/A'
            last_activity = env.properties.last_activity_time or 'N/A'
            self._logger.log(
                f'{env.id.split("/")[-1]:<44} {env.properties.displayName:<{max_display_name_length}} {created_by:<20} {env.properties.createdTime:<30} {last_activity:<30} {env.properties.environmentSku:<10}')
        self._logger.log()

    def _notify_user(self, total_envs: int):
        if total_envs > self._MAX_ENVIRONMENTS_TO_SCAN:
            self._logger.log(f'The number of environments exceeds {self._MAX_ENVIRONMENTS_TO_SCAN}. '
                  f'Scanning only the selected environments due to runtime limitations.')

    @staticmethod
    def _get_request_url() -> str:
        url = 'https://api.bap.microsoft.com/providers/Microsoft.BusinessAppPlatform/scopes/admin/environments'
        params = {
            'api-version': '2021-04-01',
            '$expand': 'properties/scheduledLifecycleOperations',
            '$select': 'id,type,name,properties.displayName,properties.createdTime,properties.environmentSku,'
                       'properties.createdBy.displayName,properties.lastActivity.lastActivity.lastActivityTime,'
                       'properties.isDefault,properties.linkedEnvironmentMetadata.instanceApiUrl'
        }
        return f'{url}?{urlencode(params)}'

    def _fetch_single_page_environments(self, token: str, url: str) -> tuple[list[Environment], str]:
        res = requests.get(
            url,
            headers={'Authorization': f'Bearer {token}'}
        )
        if res.status_code != 200:
            self._logger.log(
                f"Error response from {url} (Status: {res.status_code}): {res.text}",
                log_level="error",
            )
            if res.status_code in (401, 403):
                raise InsufficientPermissionsError()
            res.raise_for_status()

        response_data = res.json()

        environments = [Environment(**env) for env in response_data.get('value', [])]
        next_page = response_data.get('nextLink', None)

        return environments, next_page

    def _fetch_environments(self, token: str) -> list[Environment]:
        next_page_url = self._get_request_url()
        all_envs = []

        while next_page_url:
            envs, next_page_url = self._fetch_single_page_environments(token=token, url=next_page_url)
            all_envs.extend(envs)

        return all_envs

    @staticmethod
    def _is_active_since(env: Environment, threshold_timestamp: float) -> bool:
        last_activity_time = env.properties.last_activity_time
        return bool(last_activity_time) and parser.isoparse(last_activity_time).timestamp() > threshold_timestamp

    @staticmethod
    def _compare_environments(env1: Environment, env2: Environment):
        # Default environment > Production > Developer > Sandbox > Other
        env_types = ['Sandbox', 'Developer', 'Production', 'Default']
        env1_sku, env2_sku = env1.properties.environmentSku, env2.properties.environmentSku
        env1_type = env_types.index(env1_sku) if env1_sku in env_types else -1
        env2_type = env_types.index(env2_sku) if env2_sku in env_types else -1
        if env2_type != env1_type:
            return env2_type - env1_type

        # If both are of the same type, prefer the one that has an activity in the last month
        threshold_date = (datetime.now() - relativedelta(days=30)).timestamp()
        env1_last_activity_in_last_month = EnvironmentsFetcher._is_active_since(env1, threshold_date)
        env2_last_activity_in_last_month = EnvironmentsFetcher._is_active_since(env2, threshold_date)
        if env2_last_activity_in_last_month != env1_last_activity_in_last_month:
            return env2_last_activity_in_last_month - env1_last_activity_in_last_month

        # If both have activity in the last month, prefer the one that was created earlier
        env1_created_time = parser.isoparse(env1.properties.createdTime).timestamp()
        env2_created_time = parser.isoparse(env2.properties.createdTime).timestamp()
        return env1_created_time - env2_created_time

    def fetch_environments(self, token) -> tuple[list[Environment], int]:
        environments = self._fetch_environments(token)
        total_envs = len(environments)
        if total_envs == 0:
            raise InsufficientPermissionsError()
        self._notify_user(total_envs)
        selected_environments: list[Environment] = sorted(
            environments, key=cmp_to_key(self._compare_environments)
        )[:self._MAX_ENVIRONMENTS_TO_SCAN]
        self._display_environments(selected_environments, total_envs)
        return selected_environments, total_envs
