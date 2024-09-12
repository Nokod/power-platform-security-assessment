import random
from typing import Union

from pydash import find, flatten, chain

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
            find(self._environments, lambda env: env.name.lower() == env_id.lower()).properties.displayName
            for env_id in environment_ids
        ]

    def _generate_env_text(self, resources: list, resource_type: str):
        apps_envs = self._get_environment_names(flatten(resources))
        envs_text = f'<b>{"</b>, <b>".join(apps_envs)}</b> environment{"" if len(apps_envs) == 1 else "s"}'
        return f'<b>{len(resources)}</b> {resource_type}{"" if len(resources) == 1 else "s"} in the {envs_text}.'

    def _generate_developer_textual_report(self, user_resources: list[UserResources], developer_type: str) -> str:
        users_count = len(user_resources)
        apps_count = sum(len(developer.apps) for developer in user_resources)
        flows_count = sum(len(developer.flows) for developer in user_resources)

        disabled_apps_count = (
            chain(user_resources)
            .flat_map(lambda developer: developer.apps)
            .filter_(lambda app: is_app_disabled(app))
            .size()
            .value()
        )
        disabled_flows_count = (
            chain(user_resources)
            .flat_map(lambda developer: developer.flows)
            .filter_(lambda flow: is_flow_disabled(flow))
            .size()
            .value()
        )
        total_disabled_count = disabled_apps_count + disabled_flows_count
        total_active_count = apps_count + flows_count - total_disabled_count

        if users_count == 0 or apps_count + flows_count == 0:
            return ""

        textual_report = (
            f'There are <b>{apps_count + flows_count}</b> different applications and flows '
            f'owned by <b>{users_count}</b> different <b>{developer_type}</b> users. '
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

        return textual_report + '<br>'

    def generate_textual_report(self, developers: Developers) -> str:
        guest_developers_textual_report = self._generate_developer_textual_report(developers.guest_developers, 'guest')
        inactive_developers_textual_report = self._generate_developer_textual_report(developers.inactive_developers, 'deleted')
        return (
            f'{guest_developers_textual_report}'
            f'{inactive_developers_textual_report}'
        )
