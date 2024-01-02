import datetime
import requests
from requests.auth import HTTPBasicAuth
import re
from datetime import datetime, timedelta

def find_alert_ids(text):
    # Using a regular expression to find all occurrences of "Elastic Alert ID" followed by its value
    matches = re.findall(r'\* *Elastic Alert ID\*: ([\w\d]+)', text)
    return matches


def get_alert_id_key(number_of_day, api_key_jira, username_jira):
    # Your JIRA details
    JIRA_EMAIL = username_jira
    JIRA_API_TOKEN = api_key_jira
    JIRA_BASE_URL = 'https://authentix.atlassian.net'

    # Endpoint URL (customize based on what you're trying to access)
    # This example assumes you're trying to fetch issues (not necessarily "alerts" as JIRA does not have a default "alert" type)
    endpoint_url = f"{JIRA_BASE_URL}/rest/api/2/search"

    # Set up the request headers
    headers = {
        'Accept': 'application/json',
        'Content-Type': 'application/json'
    }

    days_ago = (datetime.now() - timedelta(days=number_of_day)).strftime('%Y-%m-%d')

    # Build the JQL query
    jql_query = f"created >= '{days_ago}'"
    jql_query += f" AND project = ITSM"

    start_at = 0
    max_results = 50

    alert_id = {}

    while True:
        # Parameters for the request
        params = {
            'jql': jql_query,
            'fields': 'key,summary,created,description,status',  # Adjust the fields as needed
            "startAt": start_at,
            "maxResults": max_results
        }

        # Make the API request
        response = requests.get(
            endpoint_url,
            headers=headers,
            params=params,
            auth=HTTPBasicAuth(JIRA_EMAIL, JIRA_API_TOKEN)
        )

        # Parse the response
        if response.status_code == 200:
            issues = response.json().get('issues', [])
            
            for issue in issues:
                a = []
                a = find_alert_ids(issue['fields']['description'])
                for id in a:
                    if issue['fields']['summary'] == "Attempts to Brute Force a Microsoft 365 User Account" and issue['fields']['status']['name'] == "Detect & Analyze":
                        alert_id[id] = issue['key']
        else:
            print(f"Request failed with status code {response.status_code}: {response.text}")
        if len(issues) < max_results:
            break

        start_at += max_results

    return alert_id


def write_to_jira_key(issue_key, data_to_append, api_key_jira, username_jira):
    # Your JIRA details
    JIRA_EMAIL = username_jira
    JIRA_API_TOKEN = api_key_jira
    JIRA_BASE_URL = 'https://authentix.atlassian.net'

     # Endpoint to get a specific JIRA issue
    get_issue_url = f"{JIRA_BASE_URL}/rest/api/2/issue/{issue_key}"
    
    # Headers for the request
    headers = {
        "Accept": "application/json",
    }

    # Fetch the current issue details
    response = requests.get(
        get_issue_url,
        headers=headers,
        auth=HTTPBasicAuth(JIRA_EMAIL, JIRA_API_TOKEN)
    )
    
    if response.status_code != 200:
        print(f"Failed to fetch issue details. Error: {response.text}")
        return

    current_description = response.json()["fields"]["description"]

    # New description after appending the data
    new_description = current_description + "\n" + data_to_append

    # Endpoint to edit a specific JIRA issue
    edit_issue_url = f"{JIRA_BASE_URL}/rest/api/2/issue/{issue_key}"
    headers["Content-Type"] = "application/json"
    data = {
        "fields": {
            "description": new_description
        }
    }

    # Make the PUT request to update the JIRA issue
    response = requests.put(
        edit_issue_url,
        headers=headers,
        json=data,
        auth=HTTPBasicAuth(JIRA_EMAIL, JIRA_API_TOKEN)
    )
    
    if response.status_code == 204:
        print(f"Description for issue {issue_key} updated successfully!")
    else:
        print(f"Failed to update description for issue {issue_key}. Error: {response.text}")

