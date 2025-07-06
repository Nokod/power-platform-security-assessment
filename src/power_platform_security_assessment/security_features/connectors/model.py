from pydantic import BaseModel

from power_platform_security_assessment.base_classes import ConnectorWithConnections


class ConnectorsAnalysisResult(BaseModel):
    deprecated_connectors: list[ConnectorWithConnections]
    untrusted_connectors: list[ConnectorWithConnections]


class ConnectorsAnalysisReport(BaseModel):
    connectors_info: ConnectorsAnalysisResult
    textual_report: str
