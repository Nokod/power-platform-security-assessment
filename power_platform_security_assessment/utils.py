from dateutil import parser

from power_platform_security_assessment.consts import ComponentType
from power_platform_security_assessment.security_features.common import get_application_owner_id, \
    get_cloud_flow_owner_id, get_desktop_flow_owner_id, get_model_driven_app_owner_id
from datetime import datetime


def get_environment_developers_count(environment_results) -> int:
    component_mappings = {
        ComponentType.APPLICATIONS: get_application_owner_id,
        ComponentType.CLOUD_FLOWS: get_cloud_flow_owner_id,
        ComponentType.DESKTOP_FLOWS: get_desktop_flow_owner_id,
        ComponentType.MODEL_DRIVEN_APPS: get_model_driven_app_owner_id,
    }

    # Use a set to store unique developer IDs
    developers = {
        user_id
        for component_type, get_owner_id in component_mappings.items()
        for component in environment_results[component_type].value
        if (user_id := get_owner_id(component))
    }

    return len(developers)


def round_time_to_seconds(time: str):
    return parser.isoparse(time).strftime('%Y/%m/%d %H:%M:%S')