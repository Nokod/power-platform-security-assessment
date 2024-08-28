from power_platform_security_assessment.base_classes import ConnectorWithConnections
from power_platform_security_assessment.security_features.common import extract_environment_ids_from_connectors
from power_platform_security_assessment.security_features.connectors.model import ConnectorsAnalysisResult


class ConnectorsAnalyzerTextualReport:

    @staticmethod
    def _generate_textual_report_for_type(connectors: list[ConnectorWithConnections], connector_type: str) -> str:
        connectors_count = len(connectors)
        if connectors_count == 0:
            return ""

        connections_count = sum(len(connector.connections) for connector in connectors)
        environments_count = len(extract_environment_ids_from_connectors(connectors))

        textual_report = (
            f'There {"is" if connectors_count == 1 else "are"} {connectors_count} {connector_type} connector{"" if connectors_count == 1 else "s"} '
            f'in {environments_count} environment{"" if environments_count == 1 else "s"}. '
            f'{"This" if connectors_count == 1 else "These"} connector{"" if connectors_count == 1 else "s"} '
            f'hold{"s" if connectors_count == 1 else ""} {connections_count} connection instance{"" if connections_count == 1 else "s"}.\n'
        )

        example_connector = connectors[0]
        example_connector_connections_count = len(example_connector.connections)
        textual_report += (
            f'For example, the connector {example_connector.connector.properties.displayName} is {connector_type}, and '
            f'{example_connector_connections_count} connection instance{"" if example_connector_connections_count == 1 else "s"} '
            f'{"is" if example_connector_connections_count == 1 else "are"} found in your organization.\n'
        )

        return textual_report

    def generate_textual_report(self, connectors_info: ConnectorsAnalysisResult) -> str:
        deprecated_connectors_text = self._generate_textual_report_for_type(connectors_info.deprecated_connectors, "deprecated")
        untrusted_connectors_text = self._generate_textual_report_for_type(connectors_info.untrusted_connectors, "untrusted")
        return (
            f'{deprecated_connectors_text}\n'
            f'{untrusted_connectors_text}\n'
        )
