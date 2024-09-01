import re

from power_platform_security_assessment.base_classes import User

_ENV_ID_PATTERN = r"/environments/([^/]+)"


def extract_environment_id(resource_id: str) -> str:
    match = re.search(_ENV_ID_PATTERN, resource_id)
    return match.group(1)


def extract_user_domain(user: User) -> str:
    return user.domainname.split("@")[1].split(".")[0] if '@' in user.domainname else user.domainname
