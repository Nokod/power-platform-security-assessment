from urllib.parse import urlencode

from pydash import map_, filter_

from power_platform_security_assessment.base_classes import Connector, Connection, ConnectorWithConnections
from power_platform_security_assessment.consts import Requests
from power_platform_security_assessment.fetchers.base_resource_fetcher import BaseResourceFetcher
from power_platform_security_assessment.token_manager import TokenManager


class _ConnectionWithConnectorName(Connection):
    connector_name: str


class ConnectionsFetcher(BaseResourceFetcher):
    _CONNECTORS_URL = 'https://api.powerapps.com/api/invoke'
    _IGNORED_CONNECTORS = ['shared_logicflows']

    def __init__(self, env_id: str, token_manager: TokenManager):
        super().__init__(env_id, token_manager)

    def _get_all_connections_url(self):
        params = {"api-version": "2016-11-01"}
        return f'https://api.powerapps.com/providers/Microsoft.PowerApps/scopes/admin/environments/{self._env_id}/connections?{urlencode(params)}'

    def _fetch_connectors(self, token: str, connector_names: list[str]) -> list[Connector]:
        response_data = self._fetch_single_page(
            url=self._CONNECTORS_URL,
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

        additional_used_connectors = []
        for connector_name in connector_names:
            if connector_name not in {connector.name for connector in connectors + custom_connectors}:
                connector_data = self._fetch_single_page(
                    url=self._CONNECTORS_URL,
                    headers={
                        'x-ms-path-query': f'/providers/Microsoft.PowerApps/apis/{connector_name}?showApisWithToS=true&$expand=permissions&$filter=environment eq \'{self._env_id}\'&api-version=2020-06-01',
                        'Authorization': f'Bearer {token}',
                    }
                )
                additional_used_connectors.append(Connector(**connector_data))

        return [
            connector for connector
            in connectors + custom_connectors + additional_used_connectors
            if connector.name in connector_names and connector.name not in self._IGNORED_CONNECTORS
        ]

    def _fetch_single_page_connections(self, token: str, url: str) -> tuple[list[_ConnectionWithConnectorName], str]:
        response_data = self._fetch_single_page(url, headers={
            'Authorization': f'Bearer {token}',
        })

        connections = [Connection(**connection) for connection in response_data.get('value', [])]
        connection_with_connector_name = [
            _ConnectionWithConnectorName(
                id=connection.id,
                name=connection.name,
                connector_name=connector_name,
            )
            for connection in connections
            if (connector_name := connection.id.split('/')[-3]) not in self._IGNORED_CONNECTORS
        ]
        next_page = response_data.get('nextLink', None)

        return connection_with_connector_name, next_page

    def _fetch_all_connections(self, token: str) -> list[_ConnectionWithConnectorName]:
        next_page_url = self._get_all_connections_url()
        connections: list[_ConnectionWithConnectorName] = []

        while next_page_url:
            connections_page, next_page_url = self._fetch_single_page_connections(
                token=token,
                url=next_page_url,
            )
            connections.extend(connections_page)
            self._resource_count += len(connections_page)

        return connections

    def _do_fetch_resource_data(self) -> list[ConnectorWithConnections]:
        token = self._token_manager.fetch_access_token(Requests.ENVIRONMENTS_SCOPE)
        connections = self._fetch_all_connections(token)
        used_connector_names = list({connection.connector_name for connection in connections})

        self._resource_count = 0 # Reset the resource count before fetching connectors
        connectors = self._fetch_connectors(
            token=token,
            connector_names=used_connector_names
        )

        connectors_with_connections = map_(connectors, lambda connector: ConnectorWithConnections(
            connector=connector,
            connections=filter_(connections, lambda connection: connection.connector_name == connector.name)
        ))

        # Return connectors sorted by the number of connections
        return sorted(connectors_with_connections, key=lambda x: len(x.connections), reverse=True)
