from urllib.parse import urlencode

import requests

from power_platform_security_assessment.base_resource_fetcher import BaseResourceFetcher
from power_platform_security_assessment.token_manager import TokenManager


class DesktopFlowsFetcher(BaseResourceFetcher):
    def __init__(self, instance_api_url: str, env_id: str, token_manager: TokenManager):
        self._instance_api_url = instance_api_url
        self._desktop_flows_count = 0
        super().__init__(env_id, token_manager)

    def _get_desktop_flows_url(self):
        params = {
            "$select": "name",
            "$count": "true",
            "$filter": "category eq 6",
        }
        return f'{self._instance_api_url}/api/data/v9.2/workflows?{urlencode(params)}'

    def _fetch_desktop_flows(self):
        token = self._token_manager.fetch_access_token(scope=[f'{self._instance_api_url}/.default'])
        res = requests.get(
            self._get_desktop_flows_url(),
            headers={
                'Authorization': f'Bearer {token}',
                'Prefer': 'odata.maxpagesize=1',
            }
        )

        response_data = res.json()
        return response_data.get('@odata.count', 0)

    def fetch_desktop_flows_count(self):
        return self._fetch_desktop_flows()
