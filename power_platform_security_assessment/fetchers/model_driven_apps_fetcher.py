from urllib.parse import urlencode

from power_platform_security_assessment.base_classes import ModelDrivenApp
from power_platform_security_assessment.fetchers.base_resource_fetcher import BaseResourceFetcher
from power_platform_security_assessment.token_manager import TokenManager


class ModelDrivenAppsFetcher(BaseResourceFetcher):
    def __init__(self, instance_api_url: str, env_id: str, token_manager: TokenManager):
        self._instance_api_url = instance_api_url
        super().__init__(env_id, token_manager)

    def _get_request_url(self):
        params = {
            "$select": "appmoduleidunique,statecode",
        }
        return f'{self._instance_api_url}/api/data/v9.2/appmodules/Microsoft.Dynamics.CRM.RetrieveUnpublishedMultiple()?{urlencode(params)}'

    def _fetch_single_page_model_driven_apps(self, token: str, url: str):
        response_data = self._fetch_single_page(url, headers={
            'Authorization': f'Bearer {token}',
        })

        model_driven_apps = [ModelDrivenApp(**app) for app in response_data.get('value', [])]
        next_page = response_data.get('@odata.nextLink', None)

        return model_driven_apps, next_page

    def _fetch_model_driven_apps(self) -> list[ModelDrivenApp]:
        token = self._token_manager.fetch_access_token(scope=[f'{self._instance_api_url}/.default'])
        next_page_url = self._get_request_url()
        all_model_driven_apps = []

        while next_page_url:
            model_driven_apps, next_page_url = self._fetch_single_page_model_driven_apps(token=token, url=next_page_url)
            all_model_driven_apps.extend(model_driven_apps)
            self._resource_count += len(model_driven_apps)

        return all_model_driven_apps

    def _do_fetch_resource_data(self) -> list[ModelDrivenApp]:
        return self._fetch_model_driven_apps()
