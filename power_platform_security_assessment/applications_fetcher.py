from urllib.parse import urlencode

import msal
import requests

from power_platform_security_assessment.base_classes import Application, Environment
from power_platform_security_assessment.base_resource_fetcher import BaseResourceFetcher
from power_platform_security_assessment.consts import Requests, ResponseKeys


class ApplicationsFetcher(BaseResourceFetcher):
    def __init__(self, env_id: str, refresh_token: str, client_id: str):
        self._application_count = 0
        super().__init__(env_id, refresh_token, client_id)

    def _fetch_access_token(self) -> str:
        app = msal.PublicClientApplication(self._client_id)
        result = app.acquire_token_by_refresh_token(self._refresh_token, scopes=Requests.APPLICATIONS_SCOPE)
        if ResponseKeys.ACCESS_TOKEN in result:
            return result[ResponseKeys.ACCESS_TOKEN]
        else:
            raise Exception("Failed to acquire token: %s" % result.get("error_description"))

    def _get_applications_url(self):
        environment_id_with_dot = self._env_id[:len(self._env_id) - 2] + '.' + self._env_id[len(self._env_id) - 2:]
        without_dash = environment_id_with_dot.replace('-', '')
        params = {"$select": "name", "api-version": "1"}
        return f'https://{without_dash}.environment.api.powerplatform.com/powerapps/apps?{urlencode(params)}'

    @staticmethod
    def _fetch_single_page_apps(token: str, url: str):
        res = requests.get(
            url,
            headers={
                'Authorization': f'Bearer {token}',
                'x-ms-api-context-type': 'Admin',
                'Accept-Encoding': 'gzip,deflate,compress',
            }
        )
        response_data = res.json()
        applications = [Application(**app) for app in response_data.get('value', [])]
        next_page = response_data.get('nextLink', None)

        return applications, next_page

    def _fetch_canvas_apps(self):
        token = self._fetch_access_token()
        next_page_url = self._get_applications_url()

        while next_page_url:
            applications, next_page_url = self._fetch_single_page_apps(token=token, url=next_page_url)
            self._application_count += len(applications)

        return self._application_count

    def fetch_application_count(self):
        return self._fetch_canvas_apps()
