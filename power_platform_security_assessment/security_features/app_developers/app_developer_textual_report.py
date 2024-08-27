from typing import Union

from pydash import find, flatten

from power_platform_security_assessment.base_classes import Environment, Application, CloudFlow, User
from power_platform_security_assessment.security_features.app_developers.model import UserResources, Developers


class AppDeveloperTextualReport:
    def __init__(self, environments: list[Environment]):
        self.environments = environments

    def _get_environment_names(self, apps: list[Union[Application, CloudFlow]]) -> list[str]:
        environment_ids = {app.id.split('/')[-3] for app in apps}
        return [
            find(self.environments, lambda env: env.name.lower() == env_id.lower()).properties.displayName
            for env_id in environment_ids
        ]

    def _generate_env_text(self, resources_dict: dict, resource_type: str):
        apps_envs = self._get_environment_names(flatten(resources_dict.values()))
        envs_text = f'{apps_envs[0]} environment' if len(apps_envs) == 1 else f'{", ".join(apps_envs)} environments'
        return f'{len(resources_dict)} {resource_type} in {envs_text}'

    def _generate_developer_textual_report(self, user_resources: dict[User, UserResources], developer_type: str) -> str:
        users_count = len(user_resources)
        apps_count = sum(len(developer.apps) for developer in user_resources.values())
        flows_count = sum(len(developer.flows) for developer in user_resources.values())

        if users_count == 0 or apps_count + flows_count == 0:
            return ""

        textual_report = (
            f'There are {apps_count + flows_count} different applications and flows '
            f'owned by {users_count} different {developer_type} users.\n'
        )

        user, resources = next(iter(user_resources.items()))
        textual_report += f'For example, {user.fullname} from {user.domainname.split("@")[1].split(".")[0]} developed '

        if resources.apps:
            textual_report += self._generate_env_text(resources.apps, 'applications')

        if resources.flows:
            if resources.apps:
                textual_report += ' and '  # Add "and" only if there are apps
            textual_report += self._generate_env_text(resources.flows, 'flows')

        return textual_report

    def generate_textual_report(self, developers: Developers) -> str:
        textual_report = ''
        textual_report += self._generate_developer_textual_report(developers.guest_developers, 'guest') + '\n'
        textual_report += self._generate_developer_textual_report(developers.inactive_developers, 'deleted')
        return textual_report
