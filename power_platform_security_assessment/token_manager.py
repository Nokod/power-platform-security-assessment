from typing import List

import msal

from power_platform_security_assessment.consts import ResponseKeys


class TokenManager:
    def __init__(self, client_id: str, refresh_token: str):
        self._client_id = client_id
        self._refresh_token = refresh_token

    def fetch_access_token(self, scope: List[str]) -> str:
        app = msal.PublicClientApplication(self._client_id)
        result = app.acquire_token_by_refresh_token(self._refresh_token, scopes=scope)
        if ResponseKeys.ACCESS_TOKEN in result:
            return result[ResponseKeys.ACCESS_TOKEN]
        else:
            raise Exception("Failed to acquire token: %s" % result.get("error_description"))
