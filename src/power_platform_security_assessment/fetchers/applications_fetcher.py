from urllib.parse import urlencode

from power_platform_security_assessment.base_classes import Application
from power_platform_security_assessment.consts import Requests
from power_platform_security_assessment.fetchers.base_resource_fetcher import BaseResourceFetcher
from power_platform_security_assessment.token_manager import TokenManager


class ApplicationsFetcher(BaseResourceFetcher):
    def __init__(self, env_id: str, token_manager: TokenManager):
        super().__init__(env_id, token_manager)

    def _get_request_url(self):
        environment_id_with_dot = f'{self._env_id[:-2]}.{self._env_id[-2:]}'
        without_dash = environment_id_with_dot.replace('-', '')
        params = {
            "$select": (
                "name,logicalName,properties.displayName,properties.bypassConsent,properties.owner.id,properties.createdBy.id"
                ",properties.executionRestrictions.dataLossPreventionEvaluationResult.violations"
                ",properties.executionRestrictions.appQuarantineState.quarantineStatus"
                ",properties.embeddedApp.type"
            ),
            "api-version": "1",
        }
        return f'https://{without_dash}.environment.api.powerplatform.com/powerapps/apps?{urlencode(params)}'

    def _fetch_single_page_apps(self, token: str, url: str):
        response_data = self._fetch_single_page(url, headers={
            'Authorization': f'Bearer {token}',
            'x-ms-api-context-type': 'Admin',
            'Accept-Encoding': 'gzip,deflate,compress',
        })

        applications = [Application(**app) for app in response_data.get('value', [])]
        next_page = response_data.get('nextLink', None)

        return applications, next_page

    def _fetch_canvas_apps(self) -> list[Application]:
        token = self._token_manager.fetch_access_token(Requests.APPLICATIONS_SCOPE)
        next_page_url = self._get_request_url()
        all_apps = []

        while next_page_url:
            applications, next_page_url = self._fetch_single_page_apps(token=token, url=next_page_url)
            all_apps.extend(applications)
            self._resource_count += len(applications)

        return all_apps

    def _do_fetch_resource_data(self) -> list[Application]:
        return self._fetch_canvas_apps()
