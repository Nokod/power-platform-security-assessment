from datetime import datetime, timedelta

import requests

from power_platform_security_assessment.base_classes import Environment


class EnvironmentsFetcher:
    MAX_ENVIRONMENTS_TO_SCAN = 10

    def __init__(self):
        self.environments = []

    @staticmethod
    def _display_environments(environments):
        max_display_name_length = max([len(env.properties.displayName) for env in environments])
        print(f'Total number of environments: {len(environments)}')
        print()
        print(
            f'{"ID":<44} {"Name":<{max_display_name_length}} {"Created By":<20} {"Create Time":<30} {"Last Activity":<30} {"Type":<10} {"State":<10}')
        for env in environments:
            created_by = env.properties.createdBy.get('displayName', 'N/A')
            print(
                f'{env.id.split("/")[-1]:<44} {env.properties.displayName:<{max_display_name_length}} {created_by:<20} {env.properties.createdTime:<30} {env.properties.lastModifiedTime:<30} {env.properties.environmentSku:<10} {env.properties.provisioningState:<10}')
        print()

    @staticmethod
    def _notify_user(total_envs):
        if total_envs > 10:
            print("The number of environments exceeds 10. Scanning only the default environment and the oldest "
                  "production environments with activity in the last month due to runtime limitations.")

    @staticmethod
    def _fetch_environments(token):
        res = requests.get(
            'https://api.bap.microsoft.com/providers/Microsoft.BusinessAppPlatform/scopes/admin/environments?'
            'api-version=2021-04-01&$expand=properties/scheduledLifecycleOperations',
            headers={'Authorization': f'Bearer {token}'}
        )
        return [Environment(**env) for env in res.json().get('value', [])]

    def _get_production_environments(self, environments):
        envs = [env for env in environments if env.properties.environmentSku == 'Production']
        recently_updated_envs = [env for env in envs if env.properties.lastActivity.lastActivity.lastActivityTime >= (
                datetime.now() - timedelta(days=30)).isoformat()]
        sorted_updated_envs = sorted(recently_updated_envs, key=lambda env: env.properties.createdTime)

        if len(sorted_updated_envs) > self.MAX_ENVIRONMENTS_TO_SCAN:
            return sorted_updated_envs[:self.MAX_ENVIRONMENTS_TO_SCAN]
        sorted_non_updated_envs = sorted([env for env in envs if env not in sorted_updated_envs],
                                         key=lambda env: env.properties.createdTime)
        return sorted_updated_envs + sorted_non_updated_envs[:self.MAX_ENVIRONMENTS_TO_SCAN - len(sorted_updated_envs)]

    def _filter_environments(self, environments):
        default_env = next((env for env in environments if env.properties.isDefault), None)
        production_envs = self._get_production_environments(environments)
        filtered_envs = [default_env] if default_env else []
        if len(production_envs) >= self.MAX_ENVIRONMENTS_TO_SCAN:
            return filtered_envs + production_envs[:self.MAX_ENVIRONMENTS_TO_SCAN]
        else:
            filtered_envs.extend(production_envs)
            non_production_envs = [env for env in environments if env not in production_envs and env != default_env]
            non_production_envs.sort(key=lambda env: env.properties.createdTime)
            vacant_spots = self.MAX_ENVIRONMENTS_TO_SCAN - len(filtered_envs)
            filtered_envs.extend(non_production_envs[:vacant_spots])
        return filtered_envs

    def fetch_environments(self, token) -> list[Environment]:
        environments = self._fetch_environments(token)
        total_envs = len(environments)
        self._notify_user(total_envs)
        if total_envs > 10:
            environments = self._filter_environments(environments)
        self._display_environments(environments)
        return environments
