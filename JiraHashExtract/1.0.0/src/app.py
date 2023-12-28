import re
import requests
from jira import JIRA

from walkoff_app_sdk.app_base import AppBase


class JiraHashExtract(AppBase):
    __version__ = "1.0.0"
    app_name = "JiraHashExtract"  # this needs to match "name" in api.yaml

    def __init__(self, redis, logger, console_logger=None):
        """
        Each app should have this __init__ to set up Redis and logging.
        :param redis:
        :param logger:
        :param console_logger:
        """
        super().__init__(redis, logger, console_logger)

    def get_hash(self, username, password, issue_id):
        jira = JIRA(
        server="https://authentix.atlassian.net",
        basic_auth=(username,password)
        )
        issue = jira.issue(issue_id)
        flag = 0
        id = ''
        for line in issue.fields.description.split("\n"):
            # Replace the regex with your specific hash pattern
            matches = re.findall(r'\* *Process SHA 256\*: ([\w\d]+)', line)
            if matches:
                flag = 1
                id = matches[0]
                break
        if flag == 1:
            return { "id" : id}
        else:
            return None


if __name__ == "__main__":
    JiraHashExtract.run()
