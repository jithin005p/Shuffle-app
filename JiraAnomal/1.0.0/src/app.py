import re
from jira import JIRA

from walkoff_app_sdk.app_base import AppBase


class JiraAnomal(AppBase):
    __version__ = "1.0.0"
    app_name = "JiraAnomal"  # this needs to match "name" in api.yaml

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
            return id
        else:
            return None
        
    def append_desc_vt(self, username, password, issue_id, desc):
        jira = JIRA(
        server="https://authentix.atlassian.net",
        basic_auth=(username,password)
        )
        issue = jira.issue(issue_id)
        vt_data = desc
        jira_description = ""
        jira_description += f"*VT result for {vt_data['body']['sha256']}*\n"
        jira_description += f"*Positives:* {vt_data['body']['positives']}\n"
        if vt_data['body']['positives'] != 0:
            jira_description += f"*Vendor Scan Positives:*\n"
            for key in vt_data['body']['scans']:
                if vt_data['body']['scans'][key]['detected'] == True:
                    jira_description += f"*{key} {vt_data['body']['scans'][key]['result']}*\n"

        # Append additional details to the current description
        new_description = issue.fields.description + "\n" + jira_description

        # Update the issue
        issue.update(fields={"description": new_description})


if __name__ == "__main__":
    JiraAnomal.run()
