import random
from typing import Union


from power_platform_security_assessment.base_classes import Environment, Application, CloudFlow
from power_platform_security_assessment.security_features.app_developers.model import UserResources, Developers
from power_platform_security_assessment.security_features.common import (
    extract_environment_id, extract_user_domain, is_app_disabled, is_flow_disabled
)


class AppDeveloperTextualReport:
    def __init__(self, environments: list[Environment]):
        self._environments = environments

    @staticmethod
    def _select_example_user(user_resources: list[UserResources]) -> UserResources:
        # Select a random user with at least one app or flow
        return random.choice([u for u in user_resources if len(u.apps) + len(u.flows) >= 1])

    def _get_environment_names(self, apps: list[Union[Application, CloudFlow]]) -> list[str]:
        environment_ids = {extract_environment_id(app.id) for app in apps}
        return [
            next(env for env in self._environments if env.name.lower() == env_id.lower()).properties.displayName
            for env_id in environment_ids
        ]

    def _generate_env_text(self, resources: list, resource_type: str):
        apps_envs = self._get_environment_names(resources)
        envs_text = f'<b>{"</b>, <b>".join(apps_envs)}</b> environment{"" if len(apps_envs) == 1 else "s"}'
        return f'<b>{len(resources)}</b> {resource_type}{"" if len(resources) == 1 else "s"} in the {envs_text}'

    def _generate_developer_textual_report(self, user_resources: list[UserResources], developer_type: str) -> str:
        # Only users that actually own something are developers
        user_resources = [u for u in user_resources if len(u.apps) + len(u.flows) >= 1]
        users_count = len(user_resources)
        apps_count = sum(len(developer.apps) for developer in user_resources)
        flows_count = sum(len(developer.flows) for developer in user_resources)

        disabled_apps_count = sum(
            is_app_disabled(app) for developer in user_resources for app in developer.apps
        )
        disabled_flows_count = sum(
            is_flow_disabled(flow) for developer in user_resources for flow in developer.flows
        )
        total_disabled_count = disabled_apps_count + disabled_flows_count
        total_active_count = apps_count + flows_count - total_disabled_count

        if users_count == 0 or apps_count + flows_count == 0:
            return ""

        total_count = apps_count + flows_count
        resources_text = ('There is <b>1</b> application or flow' if total_count == 1
                          else f'There are <b>{total_count}</b> different applications and flows')
        users_text = (f'<b>1</b> <b>{developer_type}</b> user' if users_count == 1
                      else f'<b>{users_count}</b> different <b>{developer_type}</b> users')
        textual_report = (
            f'{resources_text} owned by {users_text}. '
            f'<b>{total_disabled_count}</b> {"is" if total_disabled_count == 1 else "are"} disabled '
            f'and <b>{total_active_count}</b> {"is" if total_active_count == 1 else "are"} active.'
        )

        example_user = self._select_example_user(user_resources)
        textual_report += f'<br>For example, <b>{example_user.user.fullname}</b> from <b>{extract_user_domain(example_user.user)}</b> developed '

        if example_user.apps:
            textual_report += self._generate_env_text(example_user.apps, 'application')

        if example_user.flows:
            if example_user.apps:
                textual_report += ' and '  # Add "and" only if there are apps
            textual_report += self._generate_env_text(example_user.flows, 'flow')

        return textual_report + '.<br>'

    def generate_textual_report(self, developers: Developers) -> str:
        guest_developers_textual_report = self._generate_developer_textual_report(developers.guest_developers, 'guest')
        inactive_developers_textual_report = self._generate_developer_textual_report(developers.inactive_developers, 'deleted')
        return (
            f'{guest_developers_textual_report}'
            f'{inactive_developers_textual_report}'
        )
