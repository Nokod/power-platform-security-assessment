import re


from power_platform_security_assessment.base_classes import (
    User, Application, CloudFlow, ConnectorWithConnections, ModelDrivenApp, DesktopFlow
)

_ENV_ID_PATTERN = r"/environments/([^/]+)"


def extract_environment_id(resource_id: str) -> str:
    match = re.search(_ENV_ID_PATTERN, resource_id)
    return match.group(1)


def extract_environment_ids_from_connectors(connectors: list[ConnectorWithConnections]) -> list[str]:
    return list(dict.fromkeys(
        extract_environment_id(connection.id)
        for connector in connectors
        for connection in connector.connections
    ))


def extract_user_domain(user: User) -> str:
    domain_name = user.domainname
    if '#EXT#' in domain_name:
        # Guest UPNs look like "alice_contoso.com#EXT#@tenant.onmicrosoft.com" - the home domain is before #EXT#
        domain_name = domain_name.split('#EXT#')[0].replace('_', '@')
    return domain_name.split("@")[-1].split(".")[0] if '@' in domain_name else domain_name


def get_application_owner_id(app: Application) -> str:
    return app.properties.owner.id


def get_cloud_flow_owner_id(cloud_flow: CloudFlow) -> str:
    return cloud_flow.properties.creator.userId


def is_app_disabled(app: Application) -> bool:
    restrictions = app.properties.executionRestrictions
    if not restrictions:
        return False
    quarantined = bool(restrictions.appQuarantineState) and \
        restrictions.appQuarantineState.quarantineStatus == 'Quarantined'
    dlp_result = restrictions.dataLossPreventionEvaluationResult
    has_dlp_violations = bool(dlp_result) and len(dlp_result.violations or []) > 0
    return quarantined or has_dlp_violations


def is_flow_disabled(flow: CloudFlow) -> bool:
    return flow.properties.state in ['Stopped', 'Suspended']


def is_model_driven_app_disabled(model_driven_app: ModelDrivenApp) -> bool:
    return model_driven_app.statecode == 1


def is_desktop_flow_disabled(desktop_flow: DesktopFlow) -> bool:
    return desktop_flow.statecode == 1
