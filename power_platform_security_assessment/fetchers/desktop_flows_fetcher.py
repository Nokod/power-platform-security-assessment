from urllib.parse import urlencode

from power_platform_security_assessment.base_classes import DesktopFlow
from power_platform_security_assessment.fetchers.base_resource_fetcher import BaseResourceFetcher
from power_platform_security_assessment.token_manager import TokenManager


class DesktopFlowsFetcher(BaseResourceFetcher):
    def __init__(self, instance_api_url: str, env_id: str, token_manager: TokenManager):
        self._instance_api_url = instance_api_url
        super().__init__(env_id, token_manager)

    def _get_request_url(self):
        params = {
            "$select": "name,workflowidunique,statecode",
            "$count": "true",
            "$filter": "category eq 6",
        }
        return f'{self._instance_api_url}/api/data/v9.2/workflows?{urlencode(params)}'

    def _fetch_single_page_desktop_flows(self, token: str, url: str):
        response_data = self._fetch_single_page(url, headers={
            'Authorization': f'Bearer {token}',
        })

        desktop_flows = [DesktopFlow(**flow) for flow in response_data.get('value', [])]
        next_page = response_data.get('@odata.nextLink', None)

        return desktop_flows, next_page

    def _fetch_desktop_flows(self) -> list[DesktopFlow]:
        token = self._token_manager.fetch_access_token(scope=[f'{self._instance_api_url}/.default'])
        next_page_url = self._get_request_url()
        all_desktop_flows = []

        while next_page_url:
            desktop_flows, next_page_url = self._fetch_single_page_desktop_flows(token=token, url=next_page_url)
            all_desktop_flows.extend(desktop_flows)
            self._resource_count += len(desktop_flows)

        return all_desktop_flows

    def _do_fetch_resource_data(self) -> list[DesktopFlow]:
        return self._fetch_desktop_flows()
