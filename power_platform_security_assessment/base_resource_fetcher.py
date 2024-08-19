from power_platform_security_assessment.token_manager import TokenManager


class BaseResourceFetcher:
    def __init__(self, env_id: str, token_manager: TokenManager):
        self._env_id = env_id
        self._token_manager = token_manager
