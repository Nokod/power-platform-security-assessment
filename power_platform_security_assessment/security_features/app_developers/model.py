from pydantic import BaseModel

from power_platform_security_assessment.base_classes import Application, CloudFlow, User


class UserResources(BaseModel):
    user: User
    apps: list[Application]
    flows: list[CloudFlow]


class Developers(BaseModel):
    guest_developers: list[UserResources]
    inactive_developers: list[UserResources]


class AppDevelopersReport(BaseModel):
    developers_info: Developers
    textual_report: str
