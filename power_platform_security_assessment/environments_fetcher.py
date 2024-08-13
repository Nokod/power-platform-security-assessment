import requests

from power_platform_security_assessment.base_classes import Environment


class EnvironmentsFetcher:
    def __init__(self):
        self.environments = []

    @staticmethod
    def _display_environments(environments):
        print(f'Total number of environments: {len(environments)}')
        print()
        print(
            f'{"ID":<36} {"Name":<20} {"Created By":<20} {"Create Time":<30} {"Last Activity":<30} {"Type":<10} {"State":<10}')
        for env in environments:
            created_by = env.properties.createdBy.get('displayName', 'N/A')
            print(
                f'{env.id.split('/')[-1]:<36} {env.properties.displayName:<20} {created_by:<20} {env.properties.createdTime:<30} {env.properties.lastModifiedTime:<30} {env.properties.environmentSku:<10} {env.properties.provisioningState:<10}')
        print()

    @staticmethod
    def _notify_user(total_envs):
        if total_envs > 10:
            print(
                "The number of environments exceeds 10. Scanning only the default environment and the oldest 9 production environments with activity in the last month due to runtime limitations.")

    @staticmethod
    def _fetch_environments(token):
        res = requests.get(
            'https://api.bap.microsoft.com/providers/Microsoft.BusinessAppPlatform/scopes/admin/environments?api-version=2021-04-01',
            headers={'Authorization': f'Bearer {token}'})
        return [Environment(**env) for env in res.json().get('value', [])]

    @staticmethod
    def _filter_environments(environments):
        default_env = next((env for env in environments if env.properties.isDefault), None)
        production_envs = [env for env in environments if env.properties.environmentSku == 'Production']
        production_envs.sort(key=lambda env: env.properties.createdTime)
        rest_of_envs = [env for env in environments if (env not in production_envs) and (env != default_env)]
        rest_of_envs.sort(key=lambda env: env.properties.createdTime)

        filtered_envs = [default_env] if default_env else []
        vacant_spots = 9 - len(filtered_envs)
        if len(production_envs) < vacant_spots:
            filtered_envs.extend(production_envs)
            filtered_envs.extend(rest_of_envs[:vacant_spots - len(production_envs)])
        else:
            filtered_envs.extend(production_envs[:vacant_spots])
        return filtered_envs

    def fetch_environments(self, token) -> list[Environment]:
        environments = self._fetch_environments(token)
        total_envs = len(environments)
        self._notify_user(total_envs)
        if total_envs > 10:
            environments = self._filter_environments(environments)
        self._display_environments(environments)
        return environments
