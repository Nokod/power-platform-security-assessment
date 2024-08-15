from typing import Dict, Any, Optional

from pydantic import BaseModel


class LinkedEnvironmentMetadata(BaseModel):
    instanceApiUrl: str


class EnvironmentProperties(BaseModel):
    tenantId: str
    azureRegion: str
    displayName: str
    createdTime: str
    createdBy: Dict[str, Any]
    usedBy: Optional[Any] = None
    lastModifiedTime: str
    provisioningState: str
    creationType: str
    environmentSku: str
    isDefault: bool
    linkedEnvironmentMetadata: Optional[LinkedEnvironmentMetadata] = None


class Environment(BaseModel):
    id: str
    type: str
    location: str
    name: str
    properties: EnvironmentProperties


class ApplicationProperties(BaseModel):
    appVersion: str
    createdTime: str
    lastModifiedTime: str
    sharedGroupsCount: int
    sharedUsersCount: int


class Application(BaseModel):
    id: str
    name: str
    type: str
    appType: str
    properties: ApplicationProperties


class CloudFlowProperties(BaseModel):
    displayName: str
    createdTime: str
    lastModifiedTime: str
    state: str


class CloudFlow(BaseModel):
    id: str
    name: str
    type: str
    properties: CloudFlowProperties
