import re

from pydash import get, uniq

from power_platform_security_assessment.base_classes import (
    User, Application, CloudFlow, ConnectorWithConnections, ModelDrivenApp, DesktopFlow
)

_ENV_ID_PATTERN = r"/environments/([^/]+)"


def extract_environment_id(resource_id: str) -> str:
    match = re.search(_ENV_ID_PATTERN, resource_id)
    return match.group(1)


def extract_environment_ids_from_connectors(connectors: list[ConnectorWithConnections]) -> list[str]:
    return uniq(
        extract_environment_id(connection.id)
        for connector in connectors
        for connection in connector.connections
    )


def extract_user_domain(user: User) -> str:
    return user.domainname.split("@")[1].split(".")[0] if '@' in user.domainname else user.domainname


def is_app_disabled(app: Application) -> bool:
    return (get(app, 'properties.executionRestrictions.appQuarantineState.quarantineStatus') == 'Quarantined'
            or len(get(app, 'properties.executionRestrictions.dataLossPreventionEvaluationResult.violations', [])) > 0)


def is_flow_disabled(flow: CloudFlow) -> bool:
    return flow.properties.state in ['Stopped', 'Suspended']


def is_model_driven_app_disabled(model_driven_app: ModelDrivenApp) -> bool:
    return model_driven_app.statecode == 1


def is_desktop_flow_disabled(desktop_flow: DesktopFlow) -> bool:
    return desktop_flow.statecode == 1
