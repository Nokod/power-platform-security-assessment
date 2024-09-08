from datetime import datetime

import requests
from dateutil import parser
from dateutil.relativedelta import relativedelta
from pydash import find_index, chain

from power_platform_security_assessment.base_classes import Environment


class EnvironmentsFetcher:
    _MAX_ENVIRONMENTS_TO_SCAN = 10

    def __init__(self):
        self.environments = []

    @staticmethod
    def _display_environments(environments):
        max_display_name_length = max([len(env.properties.displayName) for env in environments])
        print(f'Total number of environments: {len(environments)}')
        print()
        print(
            f'{"ID":<44} {"Name":<{max_display_name_length}} {"Created By":<20} {"Create Time":<30} {"Last Activity":<30} {"Type":<10}')
        for env in environments:
            created_by = env.properties.createdBy.get('displayName', 'N/A')
            print(
                f'{env.id.split("/")[-1]:<44} {env.properties.displayName:<{max_display_name_length}} {created_by:<20} {env.properties.createdTime:<30} {env.properties.lastActivity.lastActivity.lastActivityTime:<30} {env.properties.environmentSku:<10}')
        print()

    def _notify_user(self, total_envs: int):
        if total_envs > self._MAX_ENVIRONMENTS_TO_SCAN:
            print(f'The number of environments exceeds {self._MAX_ENVIRONMENTS_TO_SCAN}. '
                  f'Scanning only the selected environments due to runtime limitations.')

    @staticmethod
    def _fetch_environments(token):
        res = requests.get(
            'https://api.bap.microsoft.com/providers/Microsoft.BusinessAppPlatform/scopes/admin/environments?'
            'api-version=2021-04-01&$expand=properties/scheduledLifecycleOperations',
            headers={'Authorization': f'Bearer {token}'}
        )
        return [Environment(**env) for env in res.json().get('value', [])]

    @staticmethod
    def _compare_environments(env1: Environment, env2: Environment):
        # Default environment > Production > Developer > Sandbox > Other
        env_types = ['Sandbox', 'Developer', 'Production', 'Default']
        env1_type = find_index(env_types, lambda env_type: env_type == env1.properties.environmentSku)
        env2_type = find_index(env_types, lambda env_type: env_type == env2.properties.environmentSku)
        if env2_type != env1_type:
            return env2_type - env1_type

        # If both are of the same type, prefer the one that has an activity in the last month
        threshold_date = (datetime.now() - relativedelta(days=30)).timestamp()
        env1_last_activity = parser.isoparse(env1.properties.lastActivity.lastActivity.lastActivityTime).timestamp()
        env2_last_activity = parser.isoparse(env2.properties.lastActivity.lastActivity.lastActivityTime).timestamp()
        env1_last_activity_in_last_month = env1_last_activity > threshold_date
        env2_last_activity_in_last_month = env2_last_activity > threshold_date
        if env2_last_activity_in_last_month != env1_last_activity_in_last_month:
            return env2_last_activity_in_last_month - env1_last_activity_in_last_month

        # If both have activity in the last month, prefer the one that was created earlier
        env1_created_time = parser.isoparse(env1.properties.createdTime).timestamp()
        env2_created_time = parser.isoparse(env2.properties.createdTime).timestamp()
        return env1_created_time - env2_created_time

    def fetch_environments(self, token) -> list[Environment]:
        environments = self._fetch_environments(token)
        total_envs = len(environments)
        self._notify_user(total_envs)
        selected_environments: list[Environment] = list(
            chain(environments)
            .sort(self._compare_environments)
            .take(self._MAX_ENVIRONMENTS_TO_SCAN)
            .value()
        )
        self._display_environments(selected_environments)
        return selected_environments
