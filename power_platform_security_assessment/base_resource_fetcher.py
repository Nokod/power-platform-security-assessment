from abc import abstractmethod

import requests

from power_platform_security_assessment.token_manager import TokenManager


class BaseResourceFetcher:
    def __init__(self, env_id: str, token_manager: TokenManager):
        self._env_id = env_id
        self._token_manager = token_manager

        self._resource_count = 0

    @abstractmethod
    def _get_request_url(self) -> str:
        raise NotImplementedError

    @staticmethod
    def _fetch_single_page(url: str, headers: dict):
        res = requests.get(url, headers=headers)
        # todo: handle errors
        return res.json()
