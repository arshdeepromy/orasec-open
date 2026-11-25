from orasec.tools.api_blackduck.api_client import BlackduckAPI
from orasec.tools.api_bugcrowd.api_client import BugcrowdAPI
from orasec.tools.api_cobalt.api_client import CobaltAPI
from orasec.tools.api_edgescan.api_client import EdgescanAPI
from orasec.tools.api_sonarqube.api_client import SonarQubeAPI
from orasec.tools.api_vulners.api_client import VulnersAPI

SCAN_APIS = {
                "Bugcrowd API": BugcrowdAPI,
                "BlackDuck API": BlackduckAPI,
                "Cobalt.io": CobaltAPI,
                "Edgescan": EdgescanAPI,
                "SonarQube": SonarQubeAPI,
                "Vulners": VulnersAPI,
             }


def create_API(tool_configuration):
    if tool_configuration.tool_type.name in SCAN_APIS:
        api_class = SCAN_APIS.get(tool_configuration.tool_type.name)
        return api_class(tool_configuration)
    return None
