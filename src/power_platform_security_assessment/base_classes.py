from typing import Dict, Any, Optional, TypeVar, Generic

from pydantic import BaseModel

T = TypeVar("T")

_PLACEHOLDER_ACTIVITY_YEAR = 9000


class LastActivityTimes(BaseModel):
    lastActivityTime: str


class LastActivity(BaseModel):
    lastActivity: LastActivityTimes


class LinkedEnvironmentMetadata(BaseModel):
    instanceApiUrl: str


class EnvironmentProperties(BaseModel):
    displayName: str
    createdTime: str
    createdBy: Dict[str, Any] = {}
    lastActivity: Optional[LastActivity] = None
    environmentSku: str
    isDefault: bool
    linkedEnvironmentMetadata: Optional[LinkedEnvironmentMetadata] = None

    @property
    def last_activity_time(self) -> Optional[str]:
        if not self.lastActivity:
            return None
        last_activity_time = self.lastActivity.lastActivity.lastActivityTime
        # The API returns a far-future placeholder (e.g. 9000-01-01) when there is no real activity date
        if last_activity_time[:4].isdigit() and int(last_activity_time[:4]) >= _PLACEHOLDER_ACTIVITY_YEAR:
            return None
        return last_activity_time


class Environment(BaseModel):
    id: str
    type: str
    name: str
    properties: EnvironmentProperties


class ApplicationUser(BaseModel):
    id: str


class DataLossPreventionEvaluationResult(BaseModel):
    violations: Optional[list] = []


class AppQuarantineState(BaseModel):
    quarantineStatus: str


class AppExecutionRestrictions(BaseModel):
    dataLossPreventionEvaluationResult: Optional[DataLossPreventionEvaluationResult] = None
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
    executionRestrictions: Optional[AppExecutionRestrictions] = None
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
    source: Optional[str] = None


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
