from enum import Enum


class Requests:
    AUTHORITY = "https://login.microsoftonline.com/common"
    CLIENT_ID = "23d8f6bd-1eb0-4cc2-a08c-7bf525c67bcd"
    ENVIRONMENTS_SCOPE = ['https://service.powerapps.com/.default']
    APPLICATIONS_SCOPE = ['https://api.powerplatform.com/.default']


class ResponseKeys:
    ACCESS_TOKEN = "access_token"


class ComponentType(Enum):
    ENVIRONMENT = 'environment'
    APPLICATIONS = 'applications'
    CLOUD_FLOWS = 'cloud_flows'
    DESKTOP_FLOWS = 'desktop_flows'
    MODEL_DRIVEN_APPS = 'model_driven_apps'
    CONNECTIONS = 'connections'
    USERS = 'users'
