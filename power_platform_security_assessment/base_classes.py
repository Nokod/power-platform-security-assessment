from typing import Dict, Any, Optional, List

from pydantic import BaseModel


class LastActivityTimes(BaseModel):
    lastActivityTime: str
    lastUpdatedTime: str


class LastActivity(BaseModel):
    lastActivity: Optional[LastActivityTimes] = None


class Properties(BaseModel):
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
    clientUris: Dict[str, str]
    runtimeEndpoints: Dict[str, str]
    databaseType: str
    trialScenarioType: str
    retentionPeriod: str
    states: Dict[str, Dict[str, Any]]
    updateCadence: Dict[str, str]
    retentionDetails: Dict[str, str]
    protectionStatus: Dict[str, str]
    cluster: Dict[str, str]
    connectedGroups: List[Any]
    lifecycleOperationsEnforcement: Dict[str, List[Dict[str, Any]]]
    governanceConfiguration: Dict[str, str]
    bingChatEnabled: bool


class Environment(BaseModel):
    id: str
    type: str
    location: str
    name: str
    properties: Properties
