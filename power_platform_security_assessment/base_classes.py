from typing import Dict, Any, Optional

from pydantic import BaseModel


class LastActivityTimes(BaseModel):
    lastActivityTime: str
    lastUpdatedTime: str


class LastActivity(BaseModel):
    lastActivity: Optional[LastActivityTimes] = None


class LinkedEnvironmentMetadata(BaseModel):
    instanceApiUrl: str


class EnvironmentProperties(BaseModel):
    tenantId: str
    azureRegion: str
    displayName: str
    createdTime: str
    createdBy: Dict[str, Any]
    usedBy: Optional[Any] = None
    lastActivity: Optional[LastActivity] = None
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


class ApplicationUser(BaseModel):
    id: str


class ApplicationProperties(BaseModel):
    appVersion: str
    createdTime: str
    lastModifiedTime: str
    sharedGroupsCount: int
    sharedUsersCount: int
    displayName: str
    bypassConsent: bool
    owner: ApplicationUser
    createdBy: ApplicationUser


class Application(BaseModel):
    id: str
    name: str
    logicalName: Optional[str] = None
    type: str
    appType: str
    properties: ApplicationProperties


class CloudFlowUser(BaseModel):
    userId: Optional[str] = None


class CloudFlowProperties(BaseModel):
    displayName: str
    createdTime: str
    lastModifiedTime: str
    state: str
    workflowEntityId: Optional[str] = None
    creator: CloudFlowUser


class CloudFlow(BaseModel):
    id: str
    name: str
    type: str
    properties: CloudFlowProperties


class User(BaseModel):
    domainname: str
    isdisabled: bool
    azurestate: int
    fullname: str
    azureactivedirectoryobjectid: str

    def __eq__(self, other):
        return self.azureactivedirectoryobjectid == other.azureactivedirectoryobjectid

    def __hash__(self):
        return hash(self.azureactivedirectoryobjectid)


class ConnectorMetadata(BaseModel):
    source: str


class ConnectorProperties(BaseModel):
    displayName: str
    metadata: ConnectorMetadata


class Connector(BaseModel):
    name: str
    properties: ConnectorProperties

    def __eq__(self, other):
        return self.name == other.name

    def __hash__(self):
        return hash(self.name)


class ConnectionExtended(BaseModel):
    name: str
    connector: Connector


class Connection(BaseModel):
    name: str
    id: str
