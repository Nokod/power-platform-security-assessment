import random

from power_platform_security_assessment.base_classes import ConnectorWithConnections
from power_platform_security_assessment.security_features.common import extract_environment_ids_from_connectors
from power_platform_security_assessment.security_features.connectors.model import ConnectorsAnalysisResult


class ConnectorsAnalyzerTextualReport:

    @staticmethod
    def _select_example_connector(connectors: list[ConnectorWithConnections]) -> ConnectorWithConnections:
        # Select a random connector with at least one connection instance
        return random.choice([c for c in connectors if len(c.connections) >= 1])

    def _generate_textual_report_for_type(self, connectors: list[ConnectorWithConnections], connector_type: str) -> str:
        connectors_count = len(connectors)
        if connectors_count == 0:
            return ""

        connections_count = sum(len(connector.connections) for connector in connectors)
        environments_count = len(extract_environment_ids_from_connectors(connectors))

        textual_report = (
            f'There {"is" if connectors_count == 1 else "are"} <b>{connectors_count} {connector_type}</b> connector{"" if connectors_count == 1 else "s"} '
            f'in {environments_count} environment{"" if environments_count == 1 else "s"}. '
            f'{"This" if connectors_count == 1 else "These"} connector{"" if connectors_count == 1 else "s"} '
            f'hold{"s" if connectors_count == 1 else ""} <b>{connections_count}</b> connection instance{"" if connections_count == 1 else "s"}.\n'
        )

        example_connector = self._select_example_connector(connectors)
        example_connector_connections_count = len(example_connector.connections)
        textual_report += (
            f'<br>For example, the connector <b>{example_connector.connector.properties.displayName}</b> is <b>{connector_type}</b>, and '
            f'<b>{example_connector_connections_count}</b> connection instance{"" if example_connector_connections_count == 1 else "s"} '
            f'{"is" if example_connector_connections_count == 1 else "are"} found in your organization.<br>'
        )

        return textual_report

    def generate_textual_report(self, connectors_info: ConnectorsAnalysisResult) -> str:
        deprecated_connectors_text = self._generate_textual_report_for_type(connectors_info.deprecated_connectors, "deprecated")
        untrusted_connectors_text = self._generate_textual_report_for_type(connectors_info.untrusted_connectors, "untrusted")
        return (
            f'{deprecated_connectors_text}\n'
            f'{untrusted_connectors_text}\n'
        )
