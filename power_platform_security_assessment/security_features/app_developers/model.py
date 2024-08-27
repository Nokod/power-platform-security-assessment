from pydantic import BaseModel

from power_platform_security_assessment.base_classes import Application, CloudFlow, User


class UserResources(BaseModel):
    apps: dict[str, list[Application]]  # app.logicalName || app.name → list of apps
    flows: dict[str, list[CloudFlow]]  # flow.properties.workflowEntityId || flow.name → list of flows


class Developers(BaseModel):
    guest_developers: dict[User, UserResources]
    inactive_developers: dict[User, UserResources]


class AppDevelopersReport(BaseModel):
    developers_info: Developers
    textual_report: str
