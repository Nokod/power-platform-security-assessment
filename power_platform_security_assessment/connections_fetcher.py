from urllib.parse import urlencode

from pydantic import BaseModel

from power_platform_security_assessment.base_classes import Connector, ConnectionExtended, Connection
from power_platform_security_assessment.base_resource_fetcher import BaseResourceFetcher
from power_platform_security_assessment.consts import Requests
from power_platform_security_assessment.token_manager import TokenManager


class ConnectionWithConnectorName(BaseModel):
    name: str
    connector_name: str


class ConnectionsFetcher(BaseResourceFetcher):
    def __init__(self, env_id: str, token_manager: TokenManager):
        super().__init__(env_id, token_manager)

    def _get_connections_for_connector_url(self, connector: Connector):
        params = {"api-version": "2016-11-01"}
        return f'https://api.powerapps.com/providers/Microsoft.PowerApps/scopes/admin/environments/{self._env_id}/apis/{connector.name}/connections?{urlencode(params)}'

    def _get_all_connections_url(self):
        params = {"api-version": "2016-11-01"}
        return f'https://api.powerapps.com/providers/Microsoft.PowerApps/scopes/admin/environments/{self._env_id}/connections?{urlencode(params)}'

    def _fetch_connectors(self, token: str, used_connectors_names: list[str]) -> list[Connector]:
        response_data = self._fetch_single_page(
            url='https://api.powerapps.com/api/invoke',
            headers={
                'x-ms-path-query': f'/providers/Microsoft.PowerApps/apis?showApisWithToS=true&$filter=environment eq \'{self._env_id}\'&api-version=2020-06-01',
                'Authorization': f'Bearer {token}',
            }
        )
        connectors = [Connector(**connector) for connector in response_data.get('value', [])]
        response_data = self._fetch_single_page(
            url=f'https://api.powerapps.com/providers/Microsoft.PowerApps/scopes/admin/environments/{self._env_id}/apis?api-version=2016-11-01',
            headers={
                'Authorization': f'Bearer {token}',
            }
        )
        custom_connectors = [Connector(**connector) for connector in response_data.get('value', [])]

        additional_used_connectors = [
            Connector(**self._fetch_single_page(
                url='https://api.powerapps.com/api/invoke',
                headers={
                    'x-ms-path-query': f'/providers/Microsoft.PowerApps/apis/{connector_name}?showApisWithToS=true&$expand=permissions&$filter=environment eq \'{self._env_id}\'&api-version=2020-06-01',
                    'Authorization': f'Bearer {token}',
                }
            ))
            for connector_name in used_connectors_names
            if connector_name not in {connector.name for connector in connectors + custom_connectors}
        ]

        return [
            connector for connector
            in connectors + custom_connectors + additional_used_connectors
            if connector.name != 'shared_logicflows'
        ]

    def _fetch_single_page_connections(self, token: str, url: str) -> tuple[list[ConnectionWithConnectorName], str]:
        response_data = self._fetch_single_page(url, headers={
            'Authorization': f'Bearer {token}',
        })

        connections = [Connection(**connection) for connection in response_data.get('value', [])]
        connection_with_connector_name = [
            ConnectionWithConnectorName(
                name=connection.name,
                connector_name=connector_name,
            )
            for connection in connections
            if (connector_name := connection.id.split('/')[-3]) != 'shared_logicflows'
        ]
        next_page = response_data.get('nextLink', None)

        return connection_with_connector_name, next_page

    def _fetch_all_connections(self, token: str) -> list[ConnectionWithConnectorName]:
        next_page_url = self._get_all_connections_url()
        connections: list[ConnectionWithConnectorName] = []

        while next_page_url:
            connections_page, next_page_url = self._fetch_single_page_connections(
                token=token,
                url=next_page_url,
            )
            connections.extend(connections_page)

        return connections

    def fetch_connections(self) -> list[ConnectionExtended]:
        token = self._token_manager.fetch_access_token(Requests.ENVIRONMENTS_SCOPE)
        connections = self._fetch_all_connections(token)
        connectors = self._fetch_connectors(
            token=token,
            used_connectors_names=list({connection.connector_name for connection in connections})
        )

        return [
            ConnectionExtended(
                name=connection.name,
                connector=next((connector for connector in connectors if connector.name == connection.connector_name), None),
            )
            for connection in connections
        ]
