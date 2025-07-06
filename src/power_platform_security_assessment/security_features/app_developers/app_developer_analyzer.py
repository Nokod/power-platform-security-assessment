from pydash import map_values, key_by, sort_by, values

from power_platform_security_assessment.base_classes import CloudFlow, Application, User, Environment
from power_platform_security_assessment.security_features.app_developers.app_developer_textual_report import AppDeveloperTextualReport
from power_platform_security_assessment.security_features.app_developers.model import UserResources, AppDevelopersReport, Developers
from power_platform_security_assessment.security_features.common import get_application_owner_id, get_cloud_flow_owner_id


class AppDeveloperAnalyzer:
    def __init__(self, apps: list[Application], cloud_flows: list[CloudFlow], users: list[User], environments: list[Environment]):
        self._apps = apps
        self._cloud_flows = cloud_flows
        self._users = users
        self._textual_report_generator = AppDeveloperTextualReport(environments)

    def _get_user_to_apps_and_flows_map(self, users: list[User]) -> list[UserResources]:
        # Create a map of user_id → UserResources
        user_map: dict[str, UserResources] = map_values(
            key_by(users, lambda user: user.azureactivedirectoryobjectid),
            lambda user: UserResources(
                user=user,
                apps=[],
                flows=[],
            )
        )

        # Map apps to their owners
        for app in self._apps:
            owner_id = get_application_owner_id(app)
            if owner_id in user_map:
                user_map[owner_id].apps.append(app)

        # Map flows to their creators
        for flow in self._cloud_flows:
            owner_id = get_cloud_flow_owner_id(flow)
            if owner_id in user_map:
                user_map[owner_id].flows.append(flow)

        # Convert the map to a list and sort it by the number of apps and flows
        return sort_by(
            values(user_map),
            lambda user_resources: len(user_resources.apps) + len(user_resources.flows),
            reverse=True,
        )

    def analyze(self) -> AppDevelopersReport:
        guest_users = []
        deleted_users = []

        for user in self._users:
            if '#EXT#' in user.domainname:
                guest_users.append(user)
            if user.azurestate in {1, 2}:
                deleted_users.append(user)

        guest_developers = self._get_user_to_apps_and_flows_map(guest_users)
        inactive_developers = self._get_user_to_apps_and_flows_map(deleted_users)

        developers_info = Developers(
            guest_developers=guest_developers,
            inactive_developers=inactive_developers,
        )
        textural_report = self._textual_report_generator.generate_textual_report(developers_info)

        return AppDevelopersReport(
            developers_info=developers_info,
            textual_report=textural_report,
        )
