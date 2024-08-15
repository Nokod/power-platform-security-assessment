class BaseResourceFetcher:
    def __init__(self, env_id: str, refresh_token: str, client_id: str):
        self._env_id = env_id
        self._refresh_token = refresh_token
        self._client_id = client_id

