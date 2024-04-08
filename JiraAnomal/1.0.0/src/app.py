import re
from jira import JIRA
import requests
from datetime import datetime, timedelta, timezone
from cbc_sdk import CBCloudAPI
from cbc_sdk.platform import Device
from collections import Counter
from requests.auth import HTTPBasicAuth
import json

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
        server="https://anomal.atlassian.net",
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
        server="https://anomal.atlassian.net",
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

    def bruteforce(self, api_key_elastic, api_key_abuse, api_key_grey, elastic_url, id_elastic):
        # Configuration
        ELASTICSEARCH_URL = elastic_url
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

        number_of_days = 5
        number_of_hours = 5

        # Define a date range for the alerts needs to be checked
        end_date = datetime.now(timezone.utc)
        start_date = end_date - timedelta(days=30)

        id = id_elastic



        SIZE = 100

        query = {
            "size": 10,
            "from": 0,
            "query": {
            "bool": {
                "filter": [
                {
                    "bool": {
                    "must": [],
                    "filter": [
                        {
                        "bool": {
                            "should": [
                            {
                                "match_phrase": {
                                "_id": id
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
                                "match_phrase": {
                                "kibana.alert.workflow_status": "acknowledged"
                                }
                            },
                            {
                                "match_phrase": {
                                "kibana.alert.workflow_status": "open"
                                }
                            },
                            {
                                "match_phrase": {
                                "kibana.alert.workflow_status": "closed"
                                }
                            }
                            ],
                            "minimum_should_match": 1
                        }
                        },
                        {
                        "range": {
                            "@timestamp": {
                            "gte": start_date.isoformat(),
                            "lt": end_date.isoformat()
                            }
                        }
                        }
                    ],
                    "should": [],
                    "must_not": []
                    }
                },
                {
                    "term": {
                    "kibana.space_ids": "default"
                    }
                }
                ]
            }
            }
        }
        jira_description = f""
        user_name = "" 
        response = requests.post(f"{ELASTICSEARCH_URL}/{INDEX_NAME}/_search",headers=HEADERS,json=query)
        if response.status_code == 200:
            hits = response.json()["hits"]["hits"][0]["_source"]
            if hits:    
                #print(hit["_source"]["kibana.alert.original_time"])
                user_name = hits["user.id"]
                org_time_str = hits["kibana.alert.original_time"]
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
                
        else:
            print(f"Error: {response.status_code}")
            print(response.text)
            jira_description += f"Error: {response.status_code}\n {response.text}" 
        return(jira_description)
                
    def get_elastic_id(self, username, password, issue_id):
        jira = JIRA(
        server="https://anomal.atlassian.net",
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
                id = matches[0]
                break
                
        if flag == 1:
            return id
        else:
            return None

    def multiple_logon_failure(self, api_key_abuse, api_key_elastic, elastic_url, id_list):
        ELASTICSEARCH_URL = elastic_url
        API_KEY = api_key_elastic

        number_of_days = 10
        # Define a date range for the alerts needs to be checked
        end_date = datetime.utcnow()
        start_date = end_date - timedelta(days=number_of_days)

        HEADERS = {
                    "Authorization": f"ApiKey {API_KEY}",
                    "Content-Type": "application/json"
                }

        INDEX_NAME = ".alerts-security.alerts-default"
        #a = id_list.split(',')
        #for b in a:
        id = id_list

        query = {
            "size": 10,
            "from": 0,
            "query": {
            "bool": {
                "filter": [
                {
                    "bool": {
                    "must": [],
                    "filter": [
                        {
                        "bool": {
                            "should": [
                            {
                                "match_phrase": {
                                "_id": id
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
                                "match_phrase": {
                                "kibana.alert.workflow_status": "acknowledged"
                                }
                            },
                            {
                                "match_phrase": {
                                "kibana.alert.workflow_status": "open"
                                }
                            },
                            {
                                "match_phrase": {
                                "kibana.alert.workflow_status": "closed"
                                }
                            }
                            ],
                            "minimum_should_match": 1
                        }
                        },
                        {
                        "range": {
                            "@timestamp": {
                            "gte": start_date.isoformat(),
                            "lt": end_date.isoformat()
                            }
                        }
                        }
                    ],
                    "should": [],
                    "must_not": []
                    }
                },
                {
                    "term": {
                    "kibana.space_ids": "default"
                    }
                }
                ]
            }
            }
        }
        jira_description = f""
        start_time = ""
        domain = ""
        hostname = ""
        user = ""
        ip = ""
        response = requests.post(f"{ELASTICSEARCH_URL}/{INDEX_NAME}/_search",headers=HEADERS,json=query)
        if response.status_code == 200:
            hits = response.json()["hits"]["hits"]
            if hits:    
                for hit in hits:
                    for key in hit['_source']:
                        if 'start' in key:
                            start_time = hit['_source'][key]
                            jira_description += f"*Start Time:* {start_time} \n"
                        if 'host' in key:
                            hostname = hit['_source'][key]['hostname']
                            jira_description += f"*Hostname:* {hostname} \n"
                        if 'source' in key:
                            #print(hit['_source'][key]['ip'])
                            ip = hit['_source'][key]['ip']
                            domain = hit['_source'][key]['domain']
                            jira_description += f"*Source IP:* {ip} \n"
                            jira_description += f"*Domain:* {domain} \n"
                        if 'user' in key:
                            #print(hit['_source'][key]['name'])
                            if 'name' in hit['_source'][key].keys():
                                user = hit['_source'][key]['name']
                            else:
                                user = ''
                            jira_description += f"*User.name:* {user} \n"
                        if 'winlog' in key:
                            subjectUsersId = hit['_source'][key]['event_data']['SubjectUserSid']
                            logonType = hit['_source'][key]['event_data']['LogonType']
                            if 'Status' in hit['_source'][key]['event_data'].keys():
                                Status = hit['_source'][key]['event_data']['Status']
                                SubStatus = hit['_source'][key]['event_data']['SubStatus']
                            else:
                                Status = ''
                                SubStatus = ''
                            TargetDomainName = hit['_source'][key]['event_data']['TargetDomainName']
                            LogonProcessName = hit['_source'][key]['event_data']['LogonProcessName']
                            AuthenticationPackageName = hit['_source'][key]['event_data']['AuthenticationPackageName']
                            if 'failure' in hit['_source'][key]['logon'].keys():
                                failureReason = hit['_source'][key]['logon']['failure']['reason']
                            else:
                                failureReason = ''
                            jira_description += f"*winlog.event_data.SubjectUserSid:* {subjectUsersId} \n"
                            jira_description += f"*winlog.event_data.LogonType:* {logonType} \n"
                            jira_description += f"*winlog.event_data.Status:* {Status} \n"
                            jira_description += f"*winlog.event_data.SubStatus:* {SubStatus} \n"
                            jira_description += f"*winlog.event_data.TargetDomainName:* {TargetDomainName} \n"
                            jira_description += f"*winlog.event_data.LogonProcessName:* {LogonProcessName} \n"
                            jira_description += f"*winlog.event_data.AuthenticationPackageName:* {AuthenticationPackageName} \n"
                            jira_description += f"*winlog.logon.failure.reason:* {failureReason} \n"
            INDEX_NAME = ".ds-logs-system.security-default*"
            jira_description += "\n\n\n"
            s_start = datetime.fromisoformat(start_time.rstrip("Z"))
            logon_start = (s_start - timedelta(hours=1)).isoformat()
            logon_end = (s_start + timedelta(hours=1)).isoformat()
            if ("2FA" not in domain):
                query =  {
                    "query":{
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
                                    "match_phrase": {
                                        "source.ip": ip
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
                                        "host.name": {
                                        "value": hostname
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
                            "format": "strict_date_optional_time",
                            "gte": logon_start,
                            "lte": logon_end
                            }
                        }
                        },
                        {
                        "match_phrase": {
                            "user.name": user
                        }
                        }
                    ],
                    "should": [],
                    "must_not": []
                    }
                }
                }
                SIZE = 100
                page = 0
                event_action = []
                while True:
                    from_parameter = page * SIZE
                    response = requests.post(f"{ELASTICSEARCH_URL}/{INDEX_NAME}/_search?from={from_parameter}&size={SIZE}",headers=HEADERS,json=query)
                    #print(response.json())
                    if response.status_code == 200:
                        #print(response.json())
                        hits = response.json()["hits"]["hits"]
                        for a in hits:
                            print(a['_source']['event']['action'])
                            action = a['_source']['event']['action']
                            if action not in event_action:
                                event_action.append(action)
                        if len(hits) < SIZE: #Last page of alert is parsed
                            break
                        page += 1
                jira_description += f"*Actions done by the user {user} from the source ip {ip} on hostname {hostname}:* \n"
                for action in event_action:
                    jira_description += f"- {action} \n"
            else:
                s_start = datetime.fromisoformat(start_time.rstrip("Z"))
                logon_start = (s_start - timedelta(days=1)).isoformat()
                logon_end = (s_start).isoformat()
                asa_query = {
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
                                                "event.dataset": {
                                                "value": "cisco_asa.log"
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
                                                "value": "logon-failed"
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
                                    "format": "strict_date_optional_time",
                                    "gte": logon_start,
                                    "lte": logon_end
                                    }
                                }
                                }
                            ],
                            "should": [],
                            "must_not": []
                            }
                        }
                }
                INDEX_NAME = ".ds-logs-cisco_asa.log*"
                ip_list = []
                page_act = 0
                SIZE = 1000
                while True:
                    from_parameter_act = page_act * SIZE
                    response = requests.post(
                        f"{ELASTICSEARCH_URL}/{INDEX_NAME}/_search?from={from_parameter_act}&size={SIZE}",
                        headers=HEADERS,
                        json=asa_query
                    )
                    if response.status_code == 200:
                        hits = response.json()["hits"]["hits"]
                        if hits:
                            for hit in hits:
                                ip_list.append(hit['_source']['source']['ip'])
                        if len(hits) < SIZE:
                            break
                        page_act += 1
                ip_counts = Counter(ip_list)

                # Sort IPs by their occurrence (descending) and then alphabetically
                sorted_ips_by_occurrence = sorted(ip_counts.items(), key=lambda x: (-x[1], x[0]))

                    # Extract sorted IPs without counts
                flag = 0
                jira_description += "*Abuse IP Check for top 5 Source IP address:*\n"
                for ip, count in sorted_ips_by_occurrence:
                    print(ip, count)
                    a = self.check_ip_abuse(ip, api_key_abuse)
                    jira_description += f"-{a} Count:{count}\n"
                    if flag == 5:
                        break
                    else:
                        flag += 1
                #print(sorted_ips_by_occurrence)
        else:
            jira_description += f"Error in fetching alert {id} \n"
        return jira_description
    
    def append_desc(self, username, password, issue_id, desc):
        jira = JIRA(
        server="https://anomal.atlassian.net",
        basic_auth=(username,password)
        )
        issue = jira.issue(issue_id)
        vt_data = desc

        # Append additional details to the current description
        new_description = issue.fields.description + "\n" + vt_data

        # Update the issue
        issue.update(fields={"description": new_description})

    def password_spraying(self, api_key_elastic, api_key_abuse, elastic_url, id_list):
        ELASTICSEARCH_URL = elastic_url
        API_KEY = api_key_elastic

        number_of_days = 10
        # Define a date range for the alerts needs to be checked
        end_date = datetime.utcnow()
        start_date = end_date - timedelta(days=number_of_days)

        HEADERS = {
                    "Authorization": f"ApiKey {API_KEY}",
                    "Content-Type": "application/json"
                }

        INDEX_NAME = ".internal.alerts-security.alerts-default*"
        id = id_list

        query = {
            "size": 10,
            "from": 0,
            "query": {
            "bool": {
                "filter": [
                {
                    "bool": {
                    "must": [],
                    "filter": [
                        {
                        "bool": {
                            "should": [
                            {
                                "match_phrase": {
                                "_id": id
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
                                "match_phrase": {
                                "kibana.alert.workflow_status": "acknowledged"
                                }
                            },
                            {
                                "match_phrase": {
                                "kibana.alert.workflow_status": "open"
                                }
                            },
                            {
                                "match_phrase": {
                                "kibana.alert.workflow_status": "closed"
                                }
                            }
                            ],
                            "minimum_should_match": 1
                        }
                        },
                        {
                        "range": {
                            "@timestamp": {
                            "gte": start_date.isoformat(),
                            "lt": end_date.isoformat()
                            }
                        }
                        }
                    ],
                    "should": [],
                    "must_not": []
                    }
                },
                {
                    "term": {
                    "kibana.space_ids": "default"
                    }
                }
                ]
            }
            }
        }
        jira_description = f""
        source_ip = ''
        spray_start = ''
        response = requests.post(f"{ELASTICSEARCH_URL}/{INDEX_NAME}/_search",headers=HEADERS,json=query)
        if response.status_code == 200:
            hits = response.json()["hits"]["hits"]
            if hits:
                #print(hits[0]['_source']['source.ip'])    
                #print(hits[0]['_source']['kibana.alert.threshold_result']['from'])   
                source_ip = hits[0]['_source']['source.ip']
                spray_start = hits[0]['_source']['kibana.alert.threshold_result']['from']       
        else:
            print("Error Fetching the issue")
        jira_description += f"- *Source.ip:* {source_ip} \n"
        jira_description += f"- *Start Time:* {spray_start} \n"

        s_start = datetime.fromisoformat(spray_start.rstrip("Z"))
        spray_start = (s_start - timedelta(hours=1)).isoformat()

        spray_end = (s_start + timedelta(hours=1)).isoformat()

        spary_inv_query = {
            "query": {
            "bool": {
            "must": [],
            "filter": [
                {
                "bool": {
                    "should": [
                    {
                        "match_phrase": {
                        "source.ip": source_ip
                        }
                    }
                    ],
                    "minimum_should_match": 1
                }
                },
                {
                "range": {
                    "@timestamp": {
                    "gte": spray_start,
                    "lte": spray_end
                    }
                }
                }
            ],
            "should": [],
            "must_not": []
            }
        }
        }
        SIZE = 100
        page = 0
        INDEX_NAME = ".ds-logs-o365.audit-default*"
        user_logged_in = []
        user_failed_login = []
        user_failure_reason = {}
        other_action = {}
        user_fail_count = {}
        while True:
            from_parameter = page * SIZE
            response = requests.post(f"{ELASTICSEARCH_URL}/{INDEX_NAME}/_search?from={from_parameter}&size={SIZE}",headers=HEADERS,json=spary_inv_query)
            if response.status_code == 200:
                hits = response.json()["hits"]["hits"]
                for a in hits:
                    if 'name' in a['_source']['user'].keys():
                        username_i = a['_source']['user']['name']
                        if username_i not in user_failure_reason.keys():
                            user_failure_reason[username_i] = []
                            other_action[username_i] = []
                        if "UserLoggedIn" in a['_source']['event']['action']:
                            #print(a['_source']['event']['action'])
                            if username_i not in user_logged_in:
                                user_logged_in.append(username_i)
                        elif "UserLoginFailed" in a['_source']['event']['action']:
                            #print(a['_source']['o365']['audit']['LogonError'])
                            if 'LogonError' in a['_source']['o365']['audit'].keys():
                                b = a['_source']['o365']['audit']['LogonError']
                                if b not in user_failure_reason[username_i]:
                                    user_failure_reason[username_i].append(b)
                            else:
                                b = ''
                            #print(b)
                            if username_i not in user_failed_login:
                                user_failed_login.append(username_i)
                                user_fail_count[username_i] = 0
                            user_fail_count[username_i] += 1
                            #print(user_failure_reason[username_i])
                        else:
                            #print(a['_source']['event']['action'])
                            b = a['_source']['event']['action']
                            if b not in other_action[username_i]:
                                other_action[username_i].append(a['_source']['event']['action'])
                if len(hits) < SIZE: #Last page of alert is parsed
                    break
                page += 1
            else:
                break
        jira_description += f"- *Users with successful login:* \n"
        if len(user_logged_in) == 0:
            jira_description += f"-- No successful login \n"
        for ul in user_logged_in:
            jira_description += f"-- {ul} \n"
        jira_description += f"- *Users with failed login:* \n"
        if len(user_failed_login) == 0:
            jira_description += f"-- No failed login \n"
        for uf in user_failed_login:
            jira_description += f"-- {uf} {user_fail_count[uf]} times\n"
        jira_description += f"- *Users logon failure reason:* \n"
        for fr in user_failure_reason:
            if len(user_failure_reason[fr]) > 0:
                jira_description += f"-- {fr}: {user_failure_reason[fr]} \n"
        jira_description += f"- *Users with other action with same source IP:* \n"
        for oa in other_action:
            jira_description += f"-- {oa}: {other_action[oa]} \n"
        jira_description += f"- *Source IP reputation (abuse.ch):* \n"
        jira_description += f"-- {self.check_ip_abuse(source_ip, api_key_abuse)}"
        return jira_description

    def vt_ip(self, api_key_vt, ip):
        url = f'https://www.virustotal.com/vtapi/v2/ip-address/report?apikey={api_key}&ip={ip_address}'
        response = requests.get(url)
        if response.status_code == 200:
            result = response.json()
            print(result)  
        else:
            print("Error:", response.status_code)
        
    def get_brute_jira(self, username, password):
        # Jira connection details
        jira_url = 'https://anomal.atlassian.net'
        jira_username = username
        jira_password = password  # Consider using API token instead of password

        # Connect to JIRA
        jira = JIRA(jira_url, basic_auth=(jira_username, jira_password))

        # JQL Query
        word_to_search = "Brute Force"  # Replace with the word you're searching for
        jql_query = f'summary ~ "{word_to_search}" AND status in ("OPEN", "DETECT & ANALYZE")'

        # Search issues
        issues = jira.search_issues(jql_query)
        return (issues[0])
    
    def printspooler(self,username, password, api_key_elastic, api_key_vt, elastic_url, cb_api_id, cb_api_key, cb_api_org, issue_id):
         # Configuration
        ELASTICSEARCH_URL = elastic_url
        INDEX_NAME = ".alerts-security.alerts-default*"  # Replace with your actual index pattern for security alerts
        API_KEY = api_key_elastic # API key of python-jithin

        VT_KEY = api_key_vt

        CB_URL = "https://defense-eu.conferdeploy.net"
        CB_API_ID = cb_api_id
        CB_API_KEY = cb_api_key
        CB_ORG_KEY = cb_api_org

        jira = JIRA(server="https://anomal.atlassian.net", basic_auth=(username,password))
        issue = jira.issue(issue_id)
        flag = 0
        id = ''
        match = []
        for line in issue.fields.description.split("\n"):
            # Replace the regex with your specific hash pattern
            matches = re.findall(r'\* *Elastic Alert ID\*: ([\w\d]+)', line)
            if len(matches) > 0:
                match.append(matches[0])


        hostname_id = {}
        alert_file_hostname = {}

        cbc_api = CBCloudAPI(url= CB_URL, token=f"{CB_API_KEY}/{CB_API_ID}",org_key=CB_ORG_KEY)

        # Add headers for the elastic search access
        HEADERS = {
            "Authorization": f"ApiKey {API_KEY}",
            "Content-Type": "application/json"
        }

        number_of_days = 10
        number_of_hours = 5

        #alert_id_dict = get_alert_id_key(number_of_days)
        #print(alert_id_dict)

        # Define a date range for the alerts needs to be checked
        end_date = datetime.utcnow()
        start_date = end_date - timedelta(days=number_of_days)

        current_datetime = datetime.today()
        current_date = current_datetime.date().isoformat()

        jira_description = ""


        SIZE = 100
        for id in match:
            # Define the query for getting the alert with Brute force as the rulename
            query = {
                    "size": 10,
                    "from": 0,
                    "query": {
                    "bool": {
                        "filter": [
                        {
                            "bool": {
                            "must": [],
                            "filter": [
                                {
                                "bool": {
                                    "should": [
                                    {
                                        "match_phrase": {
                                        "_id": id
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
                                        "match_phrase": {
                                        "kibana.alert.workflow_status": "acknowledged"
                                        }
                                    },
                                    {
                                        "match_phrase": {
                                        "kibana.alert.workflow_status": "open"
                                        }
                                    },
                                    {
                                        "match_phrase": {
                                        "kibana.alert.workflow_status": "closed"
                                        }
                                    }
                                    ],
                                    "minimum_should_match": 1
                                }
                                },
                                {
                                "range": {
                                    "@timestamp": {
                                    "gte": start_date.isoformat(),
                                    "lt": end_date.isoformat()
                                    }
                                }
                                }
                            ],
                            "should": [],
                            "must_not": []
                            }
                        },
                        {
                            "term": {
                            "kibana.space_ids": "default"
                            }
                        }
                        ]
                    }
                    }
                }
                # Send the search request to Elasticsearch
            response = requests.post(
                f"{ELASTICSEARCH_URL}/{INDEX_NAME}/_search",
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
                    alert_id = hit['_id']
                    host_name = hit['_source']['host']['hostname']
                    file_name = hit['_source']['file']['path']
                    new_path = file_name.replace('\\New', '')
                    file_name = new_path
                    #print("Alert ID: " + alert_id)
                    jira_description += f"- *Alert ID:* {alert_id} \n"
                    #print("Hostname: " + host_name)
                    jira_description += f"- *Hostname:* {host_name} \n"
                    #print("Filepath: " + file_name)
                    jira_description += f"- *Filepath:* {file_name} \n"
                    sensor = cbc_api.select(Device).where(f"name:{host_name}").first()
                    lr_session_i = sensor.lr_session()
                    command = f"powershell /c Get-FileHash -Algorithm MD5 '{file_name}' "
                    input_str = lr_session_i.create_process(rf"{command}",wait_for_completion=True, wait_for_output=True).decode('utf-8')
                    command = f"powershell /c Get-AuthenticodeSignature '{file_name}' | Format-List * "
                    sign_cb = lr_session_i.create_process(rf"{command}",wait_for_completion=True, wait_for_output=True).decode('utf-8')
                    match = re.search(r'\b[A-Fa-f0-9]{32}\b', input_str)
                    hash = match.group()
                    api_key = VT_KEY
                    file_hash = hash
                    jira_description += f"- *Hash:* {hash} \n"
                    matches = re.findall(r'CN=([\w\d]+)', sign_cb)
                    signature = matches[0]
                    matches = re.findall(r'Status                 : ([\w\d]+)', sign_cb)
                    status = matches[0]
                    jira_description += f"- *Signature Info from machine:*  \n"
                    jira_description += f"-- *Signed by:* {signature} \n"
                    jira_description += f"-- *Status:* {status} \n"

                    headers = {
                        'x-apikey': api_key,
                    }
                    response = requests.get(f'https://www.virustotal.com/api/v3/files/{file_hash}', headers=headers)
                    if response.status_code == 200:
                        # Convert response to JSON and print
                        response_data = response.json()
                        #print(response_data)
                    else:
                        print(f"Error: {response.status_code}")
                        print(response.text)
                    vt_data = response_data['data']['attributes']
                    #dict_keys(['id', 'type', 'links', 'attributes'])
                    if 'signature_info' in vt_data.keys():
                        jira_description += f"- *Signature Info from VT:* \n"
                        jira_description += f"-- *Copyright:* {str(vt_data['signature_info']['copyright'])} \n"
                    if vt_data['last_analysis_stats']['malicious'] != 0:
                        try:
                            jira_description += f"-- *Threat Name:* {vt_data['popular_threat_classification']['suggested_threat_label']} \n"
                        except:
                            i = 0
                        print(vt_data['last_analysis_stats']['malicious'])
                        jira_description += f"-- *Number of Vendors marked as Malicious:* {vt_data['last_analysis_stats']['malicious']} \n"
                    else:
                        jira_description += "-- *Veredict:* Clean \n"
            else:
                print(f"Error: {response.status_code}")
                print(response.text)
            jira_description += f"\n\n"   
        return jira_description
    
    def scan_alert(self, username, password, alert):
        # JIRA credentials and URL
        jira_url = "https://anomal.atlassian.net"

        # Construct JQL query
        one_hour_ago = (datetime.now() - timedelta(days=3)).strftime('%Y-%m-%d %H:%M')
        jql_query = f'summary ~ "{alert}" AND created >= "{one_hour_ago}"'

        # Headers for the request
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json"
        }

        # Prepare the search URL
        search_url = f'{jira_url}/rest/api/2/search'

        # Data for the POST request
        data = {
            'jql': jql_query,
            'startAt': 0,
            'maxResults': 50,  # Adjust based on your needs
            'fields': [
                'summary',
                'description',
                'created'
            ]
        }

        # Make the request to JIRA
        response = requests.post(
            search_url,
            headers=headers,
            data=json.dumps(data),
            auth=HTTPBasicAuth(username, password)
        )

        issue_list = ''

        # Check for successful response
        if response.status_code == 200:
            issues = response.json().get('issues', [])
            for issue in issues:
                if issue['key'] not in issue_list and 'Shuffle-End' not in issue['fields']['description']:
                    issue_list += issue['key']
                    issue_list += ','
        else:
            print("Failed to search JIRA issues:", response.content)
        return str(issue_list)

    def get_elastic_id_timer(self, username, password, issue_id_list):
        jira = JIRA(
        server="https://anomal.atlassian.net",
        basic_auth=(username,password)
        )
        iss = issue_id_list.split(',')
        elastic_id_list = {}
        elastic_id_list["issue"] = [] 
        for issue_id in iss:
            flag_t = {}
            if(len(issue_id)) > 0:
                issue = jira.issue(issue_id)
                flag = 0
                id = ''
                for line in issue.fields.description.split("\n"):
                    # Replace the regex with your specific hash pattern
                    matches = re.findall(r'\* *Elastic Alert ID\*: ([\w\d]+)', line)
                    if matches:
                        flag = 1
                        id = matches[0]
                        break
                        
                if flag == 1:
                    flag_t[issue_id] = id
                    elastic_id_list["issue"].append(flag_t)
        a = json.dumps(elastic_id_list)
        return (a)

    def bruteforce_timer(self, api_key_elastic, api_key_abuse, api_key_grey, elastic_url, id_elastic_list):
        # Configuration
        ELASTICSEARCH_URL = elastic_url
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

        number_of_days = 5
        number_of_hours = 5

        # Define a date range for the alerts needs to be checked
        end_date = datetime.now(timezone.utc)
        start_date = end_date - timedelta(days=30)

        jira_desc = {}
        jira_desc['issues'] = [] 


        #iss = json.loads(id_elastic_list)
        issue_json = id_elastic_list["issue"] 
        for id_elastic in issue_json:
            id = next(iter(id_elastic.values()))

            SIZE = 100

            query = {
                "size": 10,
                "from": 0,
                "query": {
                "bool": {
                    "filter": [
                    {
                        "bool": {
                        "must": [],
                        "filter": [
                            {
                            "bool": {
                                "should": [
                                {
                                    "match_phrase": {
                                    "_id": id
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
                                    "match_phrase": {
                                    "kibana.alert.workflow_status": "acknowledged"
                                    }
                                },
                                {
                                    "match_phrase": {
                                    "kibana.alert.workflow_status": "open"
                                    }
                                },
                                {
                                    "match_phrase": {
                                    "kibana.alert.workflow_status": "closed"
                                    }
                                }
                                ],
                                "minimum_should_match": 1
                            }
                            },
                            {
                            "range": {
                                "@timestamp": {
                                "gte": start_date.isoformat(),
                                "lt": end_date.isoformat()
                                }
                            }
                            }
                        ],
                        "should": [],
                        "must_not": []
                        }
                    },
                    {
                        "term": {
                        "kibana.space_ids": "default"
                        }
                    }
                    ]
                }
                }
            }
            jira_description = f""
            user_name = "" 
            response = requests.post(f"{ELASTICSEARCH_URL}/{INDEX_NAME}/_search",headers=HEADERS,json=query)
            if response.status_code == 200:
                hits = response.json()["hits"]["hits"][0]["_source"]
                if hits:    
                    #print(hit["_source"]["kibana.alert.original_time"])
                    user_name = hits["user.id"]
                    org_time_str = hits["kibana.alert.original_time"]
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
                    
            else:
                print(f"Error: {response.status_code}")
                print(response.text)
                jira_description += f"Error: {response.status_code}\n {response.text}" 
            jira_description += '\nShuffle-End\n'
            a = {}
            key = next((k for k, v in id_elastic.items() if v == id), None)
            a[key] = jira_description
            jira_desc["issues"].append(a)
        return(jira_desc)

    def append_desc_timer(self, username, password, desc):
        jira = JIRA(
        server="https://anomal.atlassian.net",
        basic_auth=(username,password)
        )
        for a in desc['issues']:
            iss = next(iter(a.values()))
            id = next((k for k, v in a.items() if v == iss), None)
            issue = jira.issue(id)
            vt_data = iss

            # Append additional details to the current description
            new_description = issue.fields.description + "\n" + vt_data

            # Update the issue
            issue.update(fields={"description": new_description})

    def password_spray_timer(self, api_key_elastic, api_key_abuse, elastic_url, id_elastic_list):
        # Configuration
        ELASTICSEARCH_URL = elastic_url
        API_KEY = api_key_elastic

        # Add headers for the elastic search access
        HEADERS = {
            "Authorization": f"ApiKey {API_KEY}",
            "Content-Type": "application/json"
        }

        # Define a date range for the alerts needs to be checked
        end_date = datetime.now(timezone.utc)
        start_date = end_date - timedelta(days=30)

        jira_desc = {}
        jira_desc['issues'] = [] 

        issue_json = id_elastic_list["issue"] 
        for id_elastic in issue_json:

            id = id = next(iter(id_elastic.values()))
            print(id)

            query = {
                "size": 10,
                "from": 0,
                "query": {
                "bool": {
                    "filter": [
                    {
                        "bool": {
                        "must": [],
                        "filter": [
                            {
                            "bool": {
                                "should": [
                                {
                                    "match_phrase": {
                                    "_id": id
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
                                    "match_phrase": {
                                    "kibana.alert.workflow_status": "acknowledged"
                                    }
                                },
                                {
                                    "match_phrase": {
                                    "kibana.alert.workflow_status": "open"
                                    }
                                },
                                {
                                    "match_phrase": {
                                    "kibana.alert.workflow_status": "closed"
                                    }
                                }
                                ],
                                "minimum_should_match": 1
                            }
                            },
                            {
                            "range": {
                                "@timestamp": {
                                "gte": start_date.isoformat(),
                                "lt": end_date.isoformat()
                                }
                            }
                            }
                        ],
                        "should": [],
                        "must_not": []
                        }
                    }
                    ]
                }
                }
            }
            jira_description = f""
            source_ip = ''
            spray_start = ''
            INDEX_NAME = ".internal.alerts-security.alerts-default*"  # Replace with your actual index pattern for security alerts
            response = requests.post(f"{ELASTICSEARCH_URL}/{INDEX_NAME}/_search",headers=HEADERS,json=query)
            if response.status_code == 200:
                hits = response.json()["hits"]["hits"]
                if hits:
                    #print(hits[0]['_source']['source.ip'])    
                    #print(hits[0]['_source']['kibana.alert.threshold_result']['from'])
                    source_ip = hits[0]['_source']['source.ip']
                    spray_start = hits[0]['_source']['kibana.alert.threshold_result']['from']  
            else:
                print("Error Fetching the issue")
            if len(spray_start) > 0:
                jira_description += f"- *Source.ip:* {source_ip} \n"
                jira_description += f"- *Start Time:* {spray_start} \n"
                ti = spray_start.rstrip('Z')
                s_start = datetime.fromisoformat(ti)
                spray_start = (s_start - timedelta(hours=1)).isoformat()

                spray_end = (s_start + timedelta(hours=1)).isoformat()

                spary_inv_query = {
                    "query": {
                    "bool": {
                    "must": [],
                    "filter": [
                        {
                        "bool": {
                            "should": [
                            {
                                "match_phrase": {
                                "source.ip": source_ip
                                }
                            }
                            ],
                            "minimum_should_match": 1
                        }
                        },
                        {
                        "range": {
                            "@timestamp": {
                            "gte": spray_start,
                            "lte": spray_end
                            }
                        }
                        }
                    ],
                    "should": [],
                    "must_not": []
                    }
                }
                }
                SIZE = 100
                page = 0
                INDEX_NAME = ".ds-logs-o365.audit-default*"
                user_logged_in = []
                user_failed_login = []
                user_failure_reason = {}
                other_action = {}
                user_fail_count = {}
                while True:
                    from_parameter = page * SIZE
                    resp = requests.post(f"{ELASTICSEARCH_URL}/{INDEX_NAME}/_search?from={from_parameter}&size={SIZE}",headers=HEADERS,json=spary_inv_query)
                    if resp.status_code == 200:
                        hi = resp.json()["hits"]["hits"]
                        for a in hi:
                            if 'name' in a['_source']['user'].keys():
                                username_i = a['_source']['user']['name']
                                if username_i not in user_failure_reason.keys():
                                    user_failure_reason[username_i] = []
                                    other_action[username_i] = []
                                    user_fail_count[username_i] = 0
                                if "UserLoggedIn" in a['_source']['event']['action']:
                                    #print(a['_source']['event']['action'])
                                    if username_i not in user_logged_in and len(user_logged_in) < 5:
                                        user_logged_in.append(username_i)
                                elif "UserLoginFailed" in a['_source']['event']['action']:
                                    #print(a['_source']['o365']['audit']['LogonError'])
                                    if 'LogonError' in a['_source']['o365']['audit'].keys():
                                        b = a['_source']['o365']['audit']['LogonError']
                                        if b not in user_failure_reason[username_i] and len(user_failure_reason[username_i]) < 5:
                                            user_failure_reason[username_i].append(b)
                                    else:
                                        b = ''
                                    #print(b)
                                    
                                    if username_i not in user_failed_login and len(user_failed_login) < 5:
                                        user_failed_login.append(username_i)
                                        user_fail_count[username_i] += 1
                                    #print(user_failure_reason[username_i])
                                else:
                                    #print(a['_source']['event']['action'])
                                    b = a['_source']['event']['action']
                                    if b not in other_action[username_i] and len(other_action[username_i]) < 5:
                                        other_action[username_i].append(a['_source']['event']['action'])
                        if len(hi) < SIZE: #Last page of alert is parsed
                            break
                        page += 1
                    else:
                        break
                jira_description += f"- *Users with successful login:* \n"
                if len(user_logged_in) == 0:
                    jira_description += f"-- No successful login \n"
                for ul in user_logged_in:
                    jira_description += f"-- {ul} \n"
                jira_description += f"- *Users with failed login:* \n"
                if len(user_failed_login) == 0:
                    jira_description += f"-- No failed login \n"
                for uf in user_failed_login:
                    jira_description += f"-- {uf} {user_fail_count[uf]} times\n"
                jira_description += f"- *Users logon failure reason:* \n"
                for fr in user_failure_reason:
                    if len(user_failure_reason[fr]) > 0:
                        jira_description += f"-- {fr}: {user_failure_reason[fr]} \n"
                jira_description += f"- *Users with other action with same source IP:* \n"
                for oa in other_action:
                    jira_description += f"-- {oa}: {other_action[oa]} \n"
                jira_description += f"- *Source IP reputation (abuse.ch):* \n"
                jira_description += f"-- {self.check_ip_abuse(source_ip, api_key_abuse)}"

                jira_description += '\nShuffle-End\n'
                b = {}
                key = next((k for k, v in id_elastic.items() if v == id), None)
                b[key] = jira_description
                jira_desc["issues"].append(b)
        return(jira_desc)
    
    def multiple_logon_failure_timer(self, api_key_abuse, api_key_elastic, elastic_url, id_list):
        ELASTICSEARCH_URL = elastic_url
        API_KEY = api_key_elastic

        number_of_days = 10
        # Define a date range for the alerts needs to be checked
        end_date = datetime.utcnow()
        start_date = end_date - timedelta(days=number_of_days)

        HEADERS = {
                    "Authorization": f"ApiKey {API_KEY}",
                    "Content-Type": "application/json"
                }

        INDEX_NAME = ".alerts-security.alerts-default"
        jira_desc = {}
        jira_desc['issues'] = [] 
        issue_json = id_list["issue"] 
        for id_elastic in issue_json:

            id = id = next(iter(id_elastic.values()))

            query = {
                "size": 10,
                "from": 0,
                "query": {
                "bool": {
                    "filter": [
                    {
                        "bool": {
                        "must": [],
                        "filter": [
                            {
                            "bool": {
                                "should": [
                                {
                                    "match_phrase": {
                                    "_id": id
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
                                    "match_phrase": {
                                    "kibana.alert.workflow_status": "acknowledged"
                                    }
                                },
                                {
                                    "match_phrase": {
                                    "kibana.alert.workflow_status": "open"
                                    }
                                },
                                {
                                    "match_phrase": {
                                    "kibana.alert.workflow_status": "closed"
                                    }
                                }
                                ],
                                "minimum_should_match": 1
                            }
                            },
                            {
                            "range": {
                                "@timestamp": {
                                "gte": start_date.isoformat(),
                                "lt": end_date.isoformat()
                                }
                            }
                            }
                        ],
                        "should": [],
                        "must_not": []
                        }
                    },
                    {
                        "term": {
                        "kibana.space_ids": "default"
                        }
                    }
                    ]
                }
                }
            }
            jira_description = f""
            start_time = ""
            domain = ""
            hostname = ""
            user = ""
            ip = ""
            response = requests.post(f"{ELASTICSEARCH_URL}/{INDEX_NAME}/_search",headers=HEADERS,json=query)
            if response.status_code == 200:
                hits = response.json()["hits"]["hits"]
                if hits:    
                    for hit in hits:
                        for key in hit['_source']:
                            if 'start' in key:
                                start_time = hit['_source'][key]
                                jira_description += f"*Start Time:* {start_time} \n"
                            if 'host' in key:
                                hostname = hit['_source'][key]['hostname']
                                jira_description += f"*Hostname:* {hostname} \n"
                            if 'source' in key:
                                #print(hit['_source'][key]['ip'])
                                ip = hit['_source'][key]['ip']
                                domain = hit['_source'][key]['domain']
                                jira_description += f"*Source IP:* {ip} \n"
                                jira_description += f"*Domain:* {domain} \n"
                            if 'user' in key:
                                #print(hit['_source'][key]['name'])
                                if 'name' in hit['_source'][key].keys():
                                    user = hit['_source'][key]['name']
                                else:
                                    user = ''
                                jira_description += f"*User.name:* {user} \n"
                            if 'winlog' in key:
                                subjectUsersId = hit['_source'][key]['event_data']['SubjectUserSid']
                                logonType = hit['_source'][key]['event_data']['LogonType']
                                if 'Status' in hit['_source'][key]['event_data'].keys():
                                    Status = hit['_source'][key]['event_data']['Status']
                                    SubStatus = hit['_source'][key]['event_data']['SubStatus']
                                else:
                                    Status = ''
                                    SubStatus = ''
                                TargetDomainName = hit['_source'][key]['event_data']['TargetDomainName']
                                LogonProcessName = hit['_source'][key]['event_data']['LogonProcessName']
                                AuthenticationPackageName = hit['_source'][key]['event_data']['AuthenticationPackageName']
                                if 'failure' in hit['_source'][key]['logon'].keys():
                                    failureReason = hit['_source'][key]['logon']['failure']['reason']
                                else:
                                    failureReason = ''
                                jira_description += f"*winlog.event_data.SubjectUserSid:* {subjectUsersId} \n"
                                jira_description += f"*winlog.event_data.LogonType:* {logonType} \n"
                                jira_description += f"*winlog.event_data.Status:* {Status} \n"
                                jira_description += f"*winlog.event_data.SubStatus:* {SubStatus} \n"
                                jira_description += f"*winlog.event_data.TargetDomainName:* {TargetDomainName} \n"
                                jira_description += f"*winlog.event_data.LogonProcessName:* {LogonProcessName} \n"
                                jira_description += f"*winlog.event_data.AuthenticationPackageName:* {AuthenticationPackageName} \n"
                                jira_description += f"*winlog.logon.failure.reason:* {failureReason} \n"
                INDEX_NAME = ".ds-logs-system.security-default*"
                jira_description += "\n\n\n"
                s_start = datetime.fromisoformat(start_time.rstrip("Z"))
                logon_start = (s_start - timedelta(hours=1)).isoformat()
                logon_end = (s_start + timedelta(hours=1)).isoformat()
                if ("2FA" not in domain):
                    query =  {
                        "query":{
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
                                        "match_phrase": {
                                            "source.ip": ip
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
                                            "host.name": {
                                            "value": hostname
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
                                "format": "strict_date_optional_time",
                                "gte": logon_start,
                                "lte": logon_end
                                }
                            }
                            },
                            {
                            "match_phrase": {
                                "user.name": user
                            }
                            }
                        ],
                        "should": [],
                        "must_not": []
                        }
                    }
                    }
                    SIZE = 100
                    page = 0
                    event_action = []
                    while True:
                        from_parameter = page * SIZE
                        response = requests.post(f"{ELASTICSEARCH_URL}/{INDEX_NAME}/_search?from={from_parameter}&size={SIZE}",headers=HEADERS,json=query)
                        #print(response.json())
                        if response.status_code == 200:
                            #print(response.json())
                            hits = response.json()["hits"]["hits"]
                            for a in hits:
                                print(a['_source']['event']['action'])
                                action = a['_source']['event']['action']
                                if action not in event_action:
                                    event_action.append(action)
                            if len(hits) < SIZE: #Last page of alert is parsed
                                break
                            page += 1
                    jira_description += f"*Actions done by the user {user} from the source ip {ip} on hostname {hostname}:* \n"
                    for action in event_action:
                        jira_description += f"- {action} \n"
                else:
                    s_start = datetime.fromisoformat(start_time.rstrip("Z"))
                    logon_start = (s_start - timedelta(days=1)).isoformat()
                    logon_end = (s_start).isoformat()
                    asa_query = {
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
                                                    "event.dataset": {
                                                    "value": "cisco_asa.log"
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
                                                    "value": "logon-failed"
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
                                        "format": "strict_date_optional_time",
                                        "gte": logon_start,
                                        "lte": logon_end
                                        }
                                    }
                                    }
                                ],
                                "should": [],
                                "must_not": []
                                }
                            }
                    }
                    INDEX_NAME = ".ds-logs-cisco_asa.log*"
                    ip_list = []
                    page_act = 0
                    SIZE = 1000
                    while True:
                        from_parameter_act = page_act * SIZE
                        response = requests.post(
                            f"{ELASTICSEARCH_URL}/{INDEX_NAME}/_search?from={from_parameter_act}&size={SIZE}",
                            headers=HEADERS,
                            json=asa_query
                        )
                        if response.status_code == 200:
                            hits = response.json()["hits"]["hits"]
                            if hits:
                                for hit in hits:
                                    ip_list.append(hit['_source']['source']['ip'])
                            if len(hits) < SIZE:
                                break
                            page_act += 1
                    ip_counts = Counter(ip_list)

                    # Sort IPs by their occurrence (descending) and then alphabetically
                    sorted_ips_by_occurrence = sorted(ip_counts.items(), key=lambda x: (-x[1], x[0]))

                        # Extract sorted IPs without counts
                    flag = 0
                    jira_description += "*Abuse IP Check for top 5 Source IP address:*\n"
                    for ip, count in sorted_ips_by_occurrence:
                        print(ip, count)
                        a = self.check_ip_abuse(ip, api_key_abuse)
                        jira_description += f"-{a} Count:{count}\n"
                        if flag == 5:
                            break
                        else:
                            flag += 1
                    #print(sorted_ips_by_occurrence)
            else:
                jira_description += f"Error in fetching alert {id} \n"
            jira_description += '\nShuffle-End\n'
            b = {}
            key = next((k for k, v in id_elastic.items() if v == id), None)
            b[key] = jira_description
            jira_desc["issues"].append(b)
        return jira_desc

    def process_termination_timer(api_key_elastic, elastic_url, api_key_vt, id_elastic_list):
        # Configuration
        ELASTICSEARCH_URL = elastic_url
        API_KEY = api_key_elastic

        # Add headers for the elastic search access
        HEADERS = {
            "Authorization": f"ApiKey {API_KEY}",
            "Content-Type": "application/json"
        }

        # Define a date range for the alerts needs to be checked
        end_date = datetime.now(timezone.utc)
        start_date = end_date - timedelta(days=30)

        jira_desc = {}
        jira_desc['issues'] = [] 

        iss = json.loads(id_elastic_list)
        issue_json = iss["issue"] 
        for id_elastic in issue_json:
            proc_name = ''
            file_name = ''
            host_name = ''
            jira_description = f""
            (key, ids), = id_elastic.items()
            for id in ids:
                query = {
                    "size": 10,
                    "from": 0,
                    "query": {
                    "bool": {
                        "filter": [
                        {
                            "bool": {
                            "must": [],
                            "filter": [
                                {
                                "bool": {
                                    "should": [
                                    {
                                        "match_phrase": {
                                        "_id": id
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
                                        "match_phrase": {
                                        "kibana.alert.workflow_status": "acknowledged"
                                        }
                                    },
                                    {
                                        "match_phrase": {
                                        "kibana.alert.workflow_status": "open"
                                        }
                                    },
                                    {
                                        "match_phrase": {
                                        "kibana.alert.workflow_status": "closed"
                                        }
                                    }
                                    ],
                                    "minimum_should_match": 1
                                }
                                },
                                {
                                "range": {
                                    "@timestamp": {
                                    "gte": start_date.isoformat(),
                                    "lt": end_date.isoformat()
                                    }
                                }
                                }
                            ],
                            "should": [],
                            "must_not": []
                            }
                        }
                        ]
                    }
                    }
                }
                source_ip = ''
                spray_start = ''
                INDEX_NAME = ".internal.alerts-security.alerts-default*"  # Replace with your actual index pattern for security alerts
                response = requests.post(f"{ELASTICSEARCH_URL}/{INDEX_NAME}/_search",headers=HEADERS,json=query)
                if response.status_code == 200:
                    hits = response.json()["hits"]["hits"]
                    if hits:
                        if 'process' in hits[0]['_source'].keys() and 'file' in hits[0]['_source'].keys():
                            proc_name = hits[0]['_source']['process']['name']
                            file_name = hits[0]['_source']['file']['name']
                        else:
                            if host_name == '':
                                host_name= hits[0]['_source']['host']['hostname']
                                proc_start = hits[0]['_source']['kibana.alert.original_time'] 
                else:
                    print("Error Fetching the issue")
                    break
            ti = proc_start.rstrip('Z')
            s_start = datetime.fromisoformat(ti)
            proc_start = (s_start - timedelta(days=30)).isoformat()
            print(proc_start)
            proc_end = (s_start + timedelta(hours=1)).isoformat()
            win_index = ".ds-logs-windows.sysmon_operational-default*"
            print(host_name)
            print(proc_name)
            print(file_name)
            proc_query = {
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
                                            "host.name": {
                                            "value": host_name
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
                                            "process.name": {
                                            "value": proc_name
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
                                            "value": "Process creation"
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
                                "format": "strict_date_optional_time",
                                "gte": proc_start,
                                "lte": proc_end
                                }
                            }
                            }
                        ],
                        "should": [],
                        "must_not": []
                        }
                    }
            }
            response = requests.post(f"{ELASTICSEARCH_URL}/{win_index}/_search",headers=HEADERS,json=proc_query)
            if response.status_code == 200:
                hits = response.json()["hits"]["hits"]
                if proc_name != "cleanmgr.exe" and len(hits) >= 1:
                    proc_hash = hits[0]['_source']['process']['hash']['sha256']
                    jira_description += f"- *Process Name:* {proc_name}\n"
                    jira_description += f"- *Hash:* {proc_hash}\n"
                else:
                    proc_hash = ''
                    jira_description += f"- *Process Name:* {proc_name}'s hash couldnt retrieve from elastic\n"
                    #VT resulkt for this hash
            #query for file , file_hash and VT result of it
            file_query = {
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
                                        "host.name": {
                                        "value": host_name
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
                                        "value": "FileDeleteDetected (File Delete logged)"
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
                                        "file.name": {
                                        "value": file_name
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
                            "format": "strict_date_optional_time",
                            "gte": proc_start,
                            "lte": proc_end
                            }
                        }
                        }
                    ],
                    "should": [],
                    "must_not": []
                    }
                }
            }
            response = requests.post(f"{ELASTICSEARCH_URL}/{win_index}/_search",headers=HEADERS,json=file_query)
            if response.status_code == 200:
                hits = response.json()["hits"]["hits"]
                file_hash = hits[0]['_source']['file']['hash']['sha256']
                jira_description += f"- *File Name:* {file_name}\n"
                jira_description += f"- *Hash:* {file_hash}\n"
            VT_KEY = api_key_vt
            headers = {
                'x-apikey': VT_KEY,
            }
            for fil_hash in [file_hash, proc_hash]:
                if len(fil_hash) > 0:
                    response = requests.get(f'https://www.virustotal.com/api/v3/files/{fil_hash}', headers=headers)
                    if response.status_code == 200:
                        # Convert response to JSON and print
                        response_data = response.json()
                    else:
                        print(f"Error: {response.status_code}")
                        print(response.text)
                    vt_data = response_data['data']['attributes']
                    #dict_keys(['id', 'type', 'links', 'attributes'])
                    if 'signature_info' in vt_data.keys():
                        jira_description += f"- *Signature Info from VT for* {fil_hash}*:* \n"
                        jira_description += f"-- *Verified:* {str(vt_data['signature_info']['verified'])} \n"
                        jira_description += f"-- *Signers:* {str(vt_data['signature_info']['signers'])} \n"
                    if vt_data['last_analysis_stats']['malicious'] != 0:
                        try:
                            jira_description += f"-- *Threat Name:* {vt_data['popular_threat_classification']['suggested_threat_label']} \n"
                        except:
                            i = 0
                        print(vt_data['last_analysis_stats']['malicious'])
                        jira_description += f"-- *Number of Vendors marked as Malicious:* {vt_data['last_analysis_stats']['malicious']} \n"
                    else:
                        jira_description += "-- *Veredict:* Clean \n"
            print(jira_description)
            jira_description += '\nShuffle-End\n'
            b = {}
            #key = next((k for k, v in id_elastic.items() if id in v), None)
            b[key] = jira_description
            jira_desc["issues"].append(b)
        return(jira_desc)

if __name__ == "__main__":
    JiraAnomal.run()
