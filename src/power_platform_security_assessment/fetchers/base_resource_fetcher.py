import time
from abc import abstractmethod

import requests
from pydash import take

from power_platform_security_assessment.base_classes import T, ResourceData
from power_platform_security_assessment.token_manager import TokenManager


class BaseResourceFetcher:
    _DEFAULT_MAX_RESOURCE_COUNT = 5000  # limit of the number of resources to fetch

    def __init__(self, env_id: str, token_manager: TokenManager):
        self._env_id = env_id
        self._token_manager = token_manager

        self._resource_count = 0
        self._max_resource_count = self._DEFAULT_MAX_RESOURCE_COUNT
        self._exceeded_max_resource_count = False

    def _retry(self, res: requests.Response, url: str, headers: dict, attempts: int):
        if attempts <= 0:
            print(f"Error: {res.status_code} while fetching {url}, response: {res.text}")
            raise Exception(f"Rate limit exceeded for {url}")

        retry_after = res.headers.get('Retry-After') or res.headers.get('retry-after')
        time.sleep(int(retry_after))
        return self._fetch_single_page(url, headers, attempts)

    def _fetch_single_page(self, url: str, headers: dict, attempts: int = 3):
        if self._resource_count >= self._max_resource_count:
            self._exceeded_max_resource_count = True
            return {}

        res = requests.get(url, headers=headers)
        if res.status_code == 429:  # Too Many Requests
            return self._retry(
                res=res,
                url=url,
                headers=headers,
                attempts=attempts - 1,
            )

        switcher = {
            200: res.json(),
            404: {},
        }

        if res.status_code not in switcher:
            res.raise_for_status()

        return switcher.get(res.status_code)

    def fetch_resource_data(self) -> ResourceData[T]:
        resource_data = self._do_fetch_resource_data()
        value = take(resource_data, self._max_resource_count)

        return ResourceData(
            value=value,
            count=len(value),
            all_resources_fetched=len(resource_data) == len(value)
                                  and not self._exceeded_max_resource_count,
        )

    @abstractmethod
    def _do_fetch_resource_data(self) -> list[T]:
        raise NotImplementedError
