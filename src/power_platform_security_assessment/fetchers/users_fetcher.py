from urllib.parse import urlencode

from power_platform_security_assessment.base_classes import User
from power_platform_security_assessment.fetchers.base_resource_fetcher import BaseResourceFetcher
from power_platform_security_assessment.token_manager import TokenManager


class UsersFetcher(BaseResourceFetcher):
    def __init__(self, instance_api_url: str, env_id: str, token_manager: TokenManager):
        self._instance_api_url = instance_api_url
        super().__init__(env_id, token_manager)
        self._max_resource_count = 50_000

    def _get_request_url(self):
        params = {
            "$select": "fullname,domainname,isdisabled,azurestate,azureactivedirectoryobjectid",
            "$filter": "azureactivedirectoryobjectid ne null and (accessmode eq 0 or accessmode eq 1 or accessmode eq 2)",
        }
        return f'{self._instance_api_url}/api/data/v9.2/systemusers?{urlencode(params)}'

    def _fetch_single_users_page(self, token: str, url: str):
        response_data = self._fetch_single_page(url, {
            'Authorization': f'Bearer {token}',
        })

        users = [User(**user) for user in response_data.get('value', [])]
        next_page = response_data.get('@odata.nextLink', None)

        return users, next_page

    def _fetch_users(self) -> list[User]:
        token = self._token_manager.fetch_access_token(scope=[f'{self._instance_api_url}/.default'])
        next_page_url = self._get_request_url()
        users_list: list[User] = []

        while next_page_url:
            users, next_page_url = self._fetch_single_users_page(token=token, url=next_page_url)
            users_list.extend(users)
            self._resource_count += len(users)

        return users_list

    def _do_fetch_resource_data(self) -> list[User]:
        return self._fetch_users()
