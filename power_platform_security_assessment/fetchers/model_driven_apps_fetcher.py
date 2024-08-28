from urllib.parse import urlencode

from power_platform_security_assessment.fetchers.base_resource_fetcher import BaseResourceFetcher
from power_platform_security_assessment.token_manager import TokenManager


class ModelDrivenAppsFetcher(BaseResourceFetcher):
    def __init__(self, instance_api_url: str, env_id: str, token_manager: TokenManager):
        self._instance_api_url = instance_api_url
        super().__init__(env_id, token_manager)

    def _get_request_url(self):
        params = {
            "$select": "appmoduleidunique",
        }
        return f'{self._instance_api_url}/api/data/v9.2/appmodules/Microsoft.Dynamics.CRM.RetrieveUnpublishedMultiple()?{urlencode(params)}'

    def _fetch_model_driven_apps(self):
        token = self._token_manager.fetch_access_token(scope=[f'{self._instance_api_url}/.default'])
        url = self._get_request_url()

        response_data = self._fetch_single_page(url, headers={
            'Authorization': f'Bearer {token}',
        })

        return len(response_data.get('value', []))

    def fetch_model_driven_apps_count(self):
        return self._fetch_model_driven_apps()
