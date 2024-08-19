from urllib.parse import urlencode

import requests

from power_platform_security_assessment.base_classes import CloudFlow
from power_platform_security_assessment.base_resource_fetcher import BaseResourceFetcher
from power_platform_security_assessment.consts import Requests
from power_platform_security_assessment.token_manager import TokenManager


class CloudFlowsFetcher(BaseResourceFetcher):
    def __init__(self, env_id: str, token_manager: TokenManager):
        self._cloud_flows_count = 0
        super().__init__(env_id, token_manager)

    def _get_cloud_flows_url(self):
        params = {"api-version": "2016-11-01"}
        return f'https://api.flow.microsoft.com/providers/Microsoft.ProcessSimple/scopes/admin/environments/{self._env_id}/v2/flows?{urlencode(params)}'

    @staticmethod
    def _fetch_single_page_cloud_flows(token: str, url: str):
        res = requests.get(
            url,
            headers={
                'Authorization': f'Bearer {token}',
                'x-ms-api-context-type': 'Admin',
                'Accept-Encoding': 'gzip,deflate,compress',
            }
        )
        response_data = res.json()
        cloud_flows = [CloudFlow(**flow) for flow in response_data.get('value', [])]
        next_page = response_data.get('nextLink', None)

        return cloud_flows, next_page

    def _fetch_cloud_flows(self):
        token = self._token_manager.fetch_access_token(Requests.SCOPE)
        next_page_url = self._get_cloud_flows_url()

        while next_page_url:
            cloud_flows, next_page_url = self._fetch_single_page_cloud_flows(token=token, url=next_page_url)
            self._cloud_flows_count += len(cloud_flows)

        return self._cloud_flows_count

    def fetch_cloud_flows_count(self):
        return self._fetch_cloud_flows()
