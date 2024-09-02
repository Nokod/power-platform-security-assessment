from typing import Dict, Any, Optional, TypeVar, Generic

from pydantic import BaseModel

T = TypeVar("T")


class LastActivityTimes(BaseModel):
    lastActivityTime: str
    lastUpdatedTime: str


class LastActivity(BaseModel):
    lastActivity: LastActivityTimes


class LinkedEnvironmentMetadata(BaseModel):
    instanceApiUrl: str


class EnvironmentProperties(BaseModel):
    tenantId: str
    azureRegion: str
    displayName: str
    createdTime: str
    createdBy: Dict[str, Any]
    usedBy: Optional[Any] = None
    lastActivity: LastActivity
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


class DataLossPreventionEvaluationResult(BaseModel):
    violations: list


class AppQuarantineState(BaseModel):
    quarantineStatus: str


class AppExecutionRestrictions(BaseModel):
    dataLossPreventionEvaluationResult: DataLossPreventionEvaluationResult
    appQuarantineState: Optional[AppQuarantineState] = None


class EmbeddedApp(BaseModel):
    type: str


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
    executionRestrictions: AppExecutionRestrictions
    embeddedApp: Optional[EmbeddedApp] = None


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


class DesktopFlow(BaseModel):
    workflowidunique: str
    statecode: int


class ModelDrivenApp(BaseModel):
    appmoduleidunique: str
    statecode: int


class User(BaseModel):
    domainname: str
    isdisabled: bool
    azurestate: int
    fullname: str
    azureactivedirectoryobjectid: str


class ConnectorMetadata(BaseModel):
    source: str


class ConnectorProperties(BaseModel):
    displayName: str
    publisher: str
    metadata: ConnectorMetadata


class Connector(BaseModel):
    name: str
    properties: ConnectorProperties


class Connection(BaseModel):
    name: str
    id: str


class ConnectorWithConnections(BaseModel):
    connector: Connector
    connections: list[Connection]


class ResourceData(BaseModel, Generic[T]):
    value: list[T] = []
    count: int = 0
    all_resources_fetched: bool = True
