from pydash import get

from power_platform_security_assessment.base_classes import ConnectorWithConnections
from power_platform_security_assessment.security_features.connectors.connectors_analyzer_textual_report import (
    ConnectorsAnalyzerTextualReport
)
from power_platform_security_assessment.security_features.connectors.deprecated_connectors import DEPRECATED_CONNECTOR_NAMES
from power_platform_security_assessment.security_features.connectors.model import ConnectorsAnalysisResult, ConnectorsAnalysisReport


class ConnectorsAnalyzer:
    def __init__(self, connectors_with_connections: list[ConnectorWithConnections]):
        self._connectors_with_connections = connectors_with_connections
        self._connectors_analysis_textual_report_generator = ConnectorsAnalyzerTextualReport()

    def analyze(self) -> ConnectorsAnalysisReport:
        deprecated_connectors = [
            c for c in self._connectors_with_connections
            if c.connector.properties.displayName.endswith(' (Deprecated)')
               or c.connector.properties.displayName in DEPRECATED_CONNECTOR_NAMES
        ]

        untrusted_connectors = [
            c for c in self._connectors_with_connections
            if get(c.connector.properties.metadata, 'source') == 'independentpublisher'
        ]

        connectors_analysis_result = ConnectorsAnalysisResult(
            deprecated_connectors=deprecated_connectors,
            untrusted_connectors=untrusted_connectors,
        )
        textual_report = self._connectors_analysis_textual_report_generator.generate_textual_report(connectors_analysis_result)

        return ConnectorsAnalysisReport(
            connectors_info=connectors_analysis_result,
            textual_report=textual_report,
        )
