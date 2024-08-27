from pydash import filter_, map_values, key_by, get, sort_by, find

from power_platform_security_assessment.base_classes import CloudFlow, Application, User, Environment
from power_platform_security_assessment.security_features.app_developers.app_developer_textual_report import AppDeveloperTextualReport
from power_platform_security_assessment.security_features.app_developers.model import UserResources, AppDevelopersReport, Developers


class AppDeveloperAnalyzer:
    def __init__(self, apps: list[Application], cloud_flows: list[CloudFlow], users: list[User], environments: list[Environment]):
        self._apps = apps
        self._cloud_flows = cloud_flows
        self._users = users
        self._textual_report_generator = AppDeveloperTextualReport(environments)

    def _get_user_to_apps_and_flows_map(self, users: list[User]) -> dict[User, UserResources]:
        # Initialize user_map with a default Developer object for each user
        user_map = map_values(key_by(users), lambda _: UserResources(apps={}, flows={}))

        # Map apps to their owners
        for app in self._apps:
            owner = find(users, lambda user: app.properties.owner.id == user.azureactivedirectoryobjectid)
            if owner:
                identifier = app.logicalName or app.name
                get(user_map, owner).apps.setdefault(identifier, []).append(app)

        # Map flows to their creators
        for flow in self._cloud_flows:
            creator = find(users, lambda user: flow.properties.creator.userId == user.azureactivedirectoryobjectid)
            if creator:
                identifier = flow.properties.workflowEntityId or flow.name
                get(user_map, creator).flows.setdefault(identifier, []).append(flow)

        # Sort the dictionary by the number of apps and flows in descending order
        return dict(sort_by(user_map.items(), lambda x: -(len(x[1].apps) + len(x[1].flows))))

    def analyze(self) -> AppDevelopersReport:
        guest_users = filter_(self._users, lambda u: u.domainname.find('#EXT#') != -1)
        deleted_users = filter_(self._users, lambda u: u.azurestate in [1, 2])

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
