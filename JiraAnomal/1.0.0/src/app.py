import re
from jira import JIRA
import requests
from datetime import datetime, timedelta
from jiraticket import get_alert_id_key, write_to_jira_key

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

    def check_ip_abuse(self, ip_address, api_key):
        """
        Check if an IP address is malicious according to AbuseIPDB records.

        :param ip_address: str, IP address to check
        :param api_key: str, AbuseIPDB API key
        :return: A dictionary with total reports and confidence score
        """
        # Set up the endpoint
        url = 'https://api.abuseipdb.com/api/v2/check'

        headers = {
            'Accept': 'application/json',
            'Key': api_key
        }

        params = {
            'ipAddress': ip_address,
            'maxAgeInDays': '90'  # check reports within the last 90 days
        }

        b = {}

        # Make the request
        response = requests.get(url, headers=headers, params=params)

        # If the request was successful, process the information
        if response.status_code == 200:
            data = response.json()
            #print(data)

            # Here, you can process the response data according to your requirements
            # For demonstration, we will just print it out
            #print(f"IP Address: {ip_address}")
            #print(f"Number of Reports: {data['data']['totalReports']}")
            #print(f"Abuse Confidence Score: {data['data']['abuseConfidenceScore']}%")

            
            b[ip_address] = {}
            b[ip_address]['Reports'] = data['data']['totalReports']
            b[ip_address]['Score'] = data['data']['abuseConfidenceScore']
            b[ip_address]['CountryCode'] = data['data']['countryCode']

            return b
            
            # You might want to make decisions based on the confidence score
            # and the number of reports. For example:
            #if data['data']['abuseConfidenceScore'] > 50:
            #    print("This IP address is suspicious!")
            #else:
            #    print("This IP address seems safe.")
        else:
            # Print out the error message in case the request was not successful
            #print(f"Error: Unable to reach AbuseIPDB, status code: {response.status_code}")
            b[ip_address] = "Error: Unable to reach AbuseIPDB"
            return b


    def check_greynoise_ip_reputation(self, ip_address, api_key):
        GREYNOISE_URL = "https://api.greynoise.io/v3/community/" + ip_address

        headers = {
            "key": api_key
        }

        i = {}

        response = requests.get(GREYNOISE_URL, headers=headers)

        # If the request was successful
        if response.status_code == 200:
            data = response.json()
            
            i[ip_address] = {}
            i[ip_address]["Noise"] = data['noise']  #Indicates whether the IP address is seen by GreyNoise scanners across the internet.
            i[ip_address]["Riot"] = data['riot']    #Stands for "Rule It Out". Indicates whether the IP is a commonly whitelisted benign service or entity.
            i[ip_address]["Classification"] = data['classification']  #The type or category of the actor or entity behind the IP.
            return i
        else:
            #print(f"Error {response.status_code}: {response.text}")
            i[ip_address] = "IP record doesnt exist in Grey Noise DB"
            return i
        

    def parse_logs(self, ELASTICSEARCH_URL, INDEX_NAME, SIZE, HEADERS, query_user, usecase, API_KEY_ABUSE, API_KEY_GREY):
        jira_description = f""
        page_act = 0
        source_ip_list = []
        source_ip_country = []
        ip_rep_abuse = {}
        ip_rep_grey = {}
        while True:
            from_parameter_act = page_act * SIZE
            response = requests.post(
                f"{ELASTICSEARCH_URL}/{INDEX_NAME}/_search?from={from_parameter_act}&size={SIZE}",
                headers=HEADERS,
                json=query_user
            )
            # Handle the response
            if response.status_code == 200:
                #print(response.json()['hits'])
                user_act = response.json()["hits"]["hits"]
                if not user_act:
                    break
                for act in user_act:
                    #print(act['_source']['source'])
                    src_ip = act['_source']['source']['ip']
                    src_country = act['_source']['source']['geo']['country_name']
                    #print(src_ip)
                    if src_ip not in source_ip_list:
                        source_ip_list.append(src_ip)
                    if src_country not in source_ip_country:
                        source_ip_country.append(src_country)
                #print(source_ip_list)
                # ABUSE IP CHECK
                for ip in source_ip_list:
                    if ip not in ip_rep_abuse.keys():
                        a = self.check_ip_abuse(ip, API_KEY_ABUSE)
                        ip_rep_abuse[ip] = a
                ############################
                #Grey Noise CHeck##########
                for ip in source_ip_list:
                    if ip not in ip_rep_grey.keys():
                        a = self.check_greynoise_ip_reputation(ip, API_KEY_GREY)
                        ip_rep_grey[ip] = a
                ###########################
            if len(user_act) < SIZE:
                break
            page_act += 1 
        jira_description += f"- *{usecase}* \n"
        jira_description += f"-- *Country*: {source_ip_country} \n"
        jira_description += f"-- *Abuse IP DB Check* \n"
        for ip in source_ip_list:
            jira_description += f"--- {ip_rep_abuse[ip]} \n"
        jira_description += f"-- *Grey Noise DB Check* \n"
        for ip in source_ip_list:
            jira_description += f"--- {ip_rep_grey[ip]} \n"
        return jira_description


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

    def bruteforce(self, api_key_elastic, api_key_abuse, api_key_grey, api_key_jira, username_jira, days):
        # Configuration
        ELASTICSEARCH_URL = "https://rychiger-siem.es.eu-central-1.aws.cloud.es.io"
        INDEX_NAME = ".internal.alerts-security.alerts-default*"  # Replace with your actual index pattern for security alerts
        API_KEY = api_key_elastic
        API_KEY_ABUSE = api_key_abuse
        API_KEY_GREY = api_key_grey


        ip_rep_abuse = {}
        ip_rep_grey = {}

        # Add headers for the elastic search access
        HEADERS = {
            "Authorization": f"ApiKey {API_KEY}",
            "Content-Type": "application/json"
        }

        number_of_days = int(days)
        number_of_hours = 5

        alert_id_dict = get_alert_id_key(number_of_days, api_key_jira, username_jira)

        # Define a date range for the alerts needs to be checked
        end_date = datetime.utcnow()
        start_date = end_date - timedelta(days=number_of_days)



        SIZE = 100

        # Define the query for getting the alert with Brute force as the rulename
        query = {
            "query": {
                "bool": {
                    "filter": [
                        {
                            "range": {
                                "@timestamp": {
                                    "gte": start_date.isoformat(),
                                    "lte": end_date.isoformat()
                                }
                            }
                        },
                        {
                            "match": {
                                "kibana.alert.rule.name": "Attempts to Brute Force a Microsoft 365 User Account"
                                #"alert.type": "security"  # Adjust based on your specific field and value for security alerts
                            }
                        }
                    ]
                }
            }
        }
        page = 0
        while True:
            from_parameter = page * SIZE
            # Send the search request to Elasticsearch
            response = requests.post(
                f"{ELASTICSEARCH_URL}/{INDEX_NAME}/_search?from={from_parameter}&size={SIZE}",
                headers=HEADERS,
                json=query
            )

            # Handle the response
            if response.status_code == 200:
                #print(response.json()['hits'])
                hits = response.json()["hits"]["hits"]
                if not hits:
                    break
                for hit in hits:
                    try:
                        #print(hit["_source"]["kibana.alert.original_time"])
                        jira_description = f""
                        alert_id = hit['_id']
                        org_time_str = hit['_source']["kibana.alert.original_time"]
                        user_name = hit['_source']["user.id"]
                        jira_description += f"- *User Name*: {user_name} \n"
                        # Convert the string to a datetime object
                        org_time = datetime.fromisoformat(org_time_str.rstrip("Z"))
                        org_start_time = org_time - timedelta(days=3)
                        org_time = org_time + timedelta(hours=1)
                        org_time_str = org_time.isoformat() + "Z"
                        org_start_time_str = org_start_time.isoformat() + "Z"
                        #print(org_start_time_str)
                        #print(org_time_str)

                        #Writing a Query for getting the activity of the user in the timeline mentioned above.
                        query_user = {
                            "query": {
                                "bool": {
                                    "filter": [
                                        {
                                            "range": {
                                                "@timestamp": {
                                                    "gte": org_start_time_str,
                                                    "lte": org_time_str
                                                }
                                            }
                                        },
                                        {
                                            "bool": {
                                                "filter": [
                                                    {
                                                        "bool": {
                                                            "should": [
                                                                {
                                                                    "term": {
                                                                        "user.id": {
                                                                            "value": user_name
                                                                        }
                                                                    }
                                                                }
                                                            ],
                                                            "minimum_should_match": 1
                                                        }
                                                    },
                                                    {
                                                        "bool": {
                                                            "should": [
                                                                {
                                                                    "term": {
                                                                        "event.action": {
                                                                            "value": "UserLoggedIn"
                                                                        }
                                                                    }
                                                                }
                                                            ],
                                                            "minimum_should_match": 1
                                                        }
                                                    }
                                                ]
                                            }
                                        }
                                    ]
                                }
                            }
                        }

                        #This is the index that contain the logs for bruteforce attack to a Microsoft 365 User
                        INDEX_NAME = ".ds-logs-o365.audit-default*"
                        usecase = "Successful Login Check"
                        jira_description += self.parse_logs(ELASTICSEARCH_URL, INDEX_NAME, SIZE, HEADERS, query_user, usecase, API_KEY_ABUSE, API_KEY_GREY)
                        ###Usecase 2 Password Guessed Correctly###################
                        query_failed = {
                            "query": {
                                "bool": {
                                    "must": [],
                                    "filter": [
                                        {
                                        "bool": {
                                            "filter": [
                                            {
                                                "bool": {
                                                "should": [
                                                    {
                                                    "term": {
                                                        "user.id": {
                                                        "value": user_name
                                                        }
                                                    }
                                                    }
                                                ],
                                                "minimum_should_match": 1
                                                }
                                            },
                                            {
                                                "bool": {
                                                "should": [
                                                    {
                                                    "term": {
                                                        "o365.audit.LogonError": {
                                                        "value": "UserStrongAuthClientAuthNRequiredInterrupt"
                                                        }
                                                    }
                                                    }
                                                ],
                                                "minimum_should_match": 1
                                                }
                                            }
                                            ]
                                        }
                                        },
                                        {
                                        "range": {
                                            "@timestamp": {
                                            "gte": org_start_time_str,
                                            "lte": org_time_str
                                            }
                                        }
                                        },
                                        {
                                        "match_phrase": {
                                            "event.action": "UserLoginFailed"
                                        }
                                        },
                                        {
                                        "match_phrase": {
                                            "o365.audit.LogonError": "UserStrongAuthClientAuthNRequiredInterrupt"
                                        }
                                        }
                                    ],
                                    "should": [],
                                    "must_not": []
                                }
                            }
                        }
                        usecase = "Successful Guess of Password Check"
                        jira_description += self.parse_logs(ELASTICSEARCH_URL, INDEX_NAME, SIZE, HEADERS, query_failed, usecase, API_KEY_ABUSE, API_KEY_GREY)  
                        try:
                            write_to_jira_key(alert_id_dict[alert_id], jira_description, api_key_jira, username_jira)          
                        except:
                            print("Exception") 
                    except:
                        print("Exception")
            else:
                print(f"Error: {response.status_code}")
                print(response.text)
            if len(hits) < SIZE: #Last page of alert is parsed
                break
            page += 1

    def get_elastic_id(self, username, password, issue_id):
        jira = JIRA(
        server="https://authentix.atlassian.net",
        basic_auth=(username,password)
        )
        issue = jira.issue(issue_id)
        flag = 0
        id = ''
        for line in issue.fields.description.split("\n"):
            # Replace the regex with your specific hash pattern
            matches = re.findall(r'\* *Elastic Alert ID\*: ([\w\d]+)', line)
            if matches:
                flag = 1
                id = matches
                break
        if flag == 1:
            return id
        else:
            return None


if __name__ == "__main__":
    JiraAnomal.run()
