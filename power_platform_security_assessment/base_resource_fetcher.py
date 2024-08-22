import time
from abc import abstractmethod

import requests

from power_platform_security_assessment.token_manager import TokenManager


class BaseResourceFetcher:
    def __init__(self, env_id: str, token_manager: TokenManager):
        self._env_id = env_id
        self._token_manager = token_manager

        self._resource_count = 0

    def _retry(self, res: requests.Response, url: str, headers: dict, attempts: int):
        if attempts <= 0:
            print(f"Error: {res.status_code} while fetching {url}, response: {res.text}")
            raise Exception(f"Rate limit exceeded for {url}")

        retry_after = res.headers.get('Retry-After') or res.headers.get('retry-after')
        time.sleep(int(retry_after))
        return self._fetch_single_page(url, headers, attempts)

    def _fetch_single_page(self, url: str, headers: dict, attempts: int = 3):
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
            403: {}, #todo: check permissions
        }

        if res.status_code not in switcher:
            print(f"Error: {res.status_code} while fetching {url}, response: {res.text}")
            res.raise_for_status()

        return switcher.get(res.status_code)
