from urllib.parse import urlencode

from power_platform_security_assessment.base_classes import CloudFlow
from power_platform_security_assessment.consts import Requests
from power_platform_security_assessment.fetchers.base_resource_fetcher import BaseResourceFetcher
from power_platform_security_assessment.token_manager import TokenManager


class CloudFlowsFetcher(BaseResourceFetcher):
    def __init__(self, env_id: str, token_manager: TokenManager):
        super().__init__(env_id, token_manager)

    def _get_request_url(self):
        params = {"api-version": "2016-11-01"}
        return f'https://api.flow.microsoft.com/providers/Microsoft.ProcessSimple/scopes/admin/environments/{self._env_id}/v2/flows?{urlencode(params)}'

    def _fetch_single_page_cloud_flows(self, token: str, url: str):
        response_data = self._fetch_single_page(url, headers={
            'Authorization': f'Bearer {token}',
            'x-ms-api-context-type': 'Admin',
            'Accept-Encoding': 'gzip,deflate,compress',
        })

        cloud_flows = [CloudFlow(**flow) for flow in response_data.get('value', [])]
        next_page = response_data.get('nextLink', None)

        return cloud_flows, next_page

    def _fetch_cloud_flows(self) -> list[CloudFlow]:
        token = self._token_manager.fetch_access_token(Requests.ENVIRONMENTS_SCOPE)
        next_page_url = self._get_request_url()
        all_cloud_flows = []

        while next_page_url:
            cloud_flows, next_page_url = self._fetch_single_page_cloud_flows(token=token, url=next_page_url)
            all_cloud_flows.extend(cloud_flows)
            self._resource_count += len(cloud_flows)

        return all_cloud_flows

    def _do_fetch_resource_data(self) -> list[CloudFlow]:
        return self._fetch_cloud_flows()
