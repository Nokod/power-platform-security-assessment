import time
from abc import abstractmethod

import requests
import json
from pydash import take

from power_platform_security_assessment.base_classes import T, ResourceData
from power_platform_security_assessment.token_manager import TokenManager
from power_platform_security_assessment.logger import Logger


class BaseResourceFetcher:
    _DEFAULT_MAX_RESOURCE_COUNT = 5000  # limit of the number of resources to fetch

    def __init__(self, env_id: str, token_manager: TokenManager, logger: Logger):
        self._env_id = env_id
        self._token_manager = token_manager
        self._logger = logger

        self._resource_count = 0
        self._max_resource_count = self._DEFAULT_MAX_RESOURCE_COUNT
        self._exceeded_max_resource_count = False

    def _retry(self, res: requests.Response, url: str, headers: dict, attempts: int):
        if attempts <= 0:
            self._logger.log(
                f"Error: {res.status_code} while fetching {url}, response: {res.text}",
                log_level="error",
            )
            raise Exception(f"Rate limit exceeded for {url}")

        retry_after = res.headers.get('Retry-After') or res.headers.get('retry-after')
        time.sleep(int(retry_after))
        return self._fetch_single_page(url, headers, attempts)

    def _fetch_single_page(self, url: str, headers: dict, attempts: int = 3):
        if self._resource_count >= self._max_resource_count:
            self._exceeded_max_resource_count = True
            self._logger.log(
                f"Reached maximum resource count limit ({self._max_resource_count}). Stopping further fetches.",
                log_level="warning",
            )
            return {}

        self._logger.log(f"Fetching URL: {url}", log_level="debug")
        res = requests.get(url, headers=headers)

        if res.status_code == 429:  # Too Many Requests
            return self._retry(
                res=res,
                url=url,
                headers=headers,
                attempts=attempts - 1,
            )

        if res.status_code == 200:
            self._logger.log(
                f"Successful response from {url} (Status: {res.status_code})",
                log_level="debug",
            )
            # Limit response size for debug output to avoid excessive logs
            response_text = res.text[:1000] + ("..." if len(res.text) > 1000 else "")
            self._logger.log(f"Response: {response_text}", log_level="debug")
        elif res.status_code == 404:
            self._logger.log(
                f"Resource not found at {url} (Status: {res.status_code})",
                log_level="warning",
            )
        else:
            self._logger.log(
                f"Error response from {url} (Status: {res.status_code}): {res.text}",
                log_level="error",
            )

        switcher = {
            200: res.json(),
            404: {},
        }

        if res.status_code not in switcher:
            res.raise_for_status()

        return switcher.get(res.status_code)

    def fetch_resource_data(self) -> ResourceData[T]:
        self._logger.log(f"Fetching resource data for environment {self._env_id}", log_level="debug")
        resource_data = self._do_fetch_resource_data()
        value = take(resource_data, self._max_resource_count)

        self._logger.log(
            f"Fetched {len(value)} resources out of {len(resource_data)} total",
            log_level="debug",
        )

        return ResourceData(
            value=value,
            count=len(value),
            all_resources_fetched=len(resource_data) == len(value)
                                  and not self._exceeded_max_resource_count,
        )

    @abstractmethod
    def _do_fetch_resource_data(self) -> list[T]:
        raise NotImplementedError
