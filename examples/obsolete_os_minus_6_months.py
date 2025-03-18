### This script dynamically creates custom security issues for obsolete operating systems and associates the affected assets with them.
### In Cyberwatch, these issues can then be used to generate alerts or integrations.

from cyberwatch_api import Cyberwatch_Pyhelper
import re
from datetime import datetime, timedelta

cbw = Cyberwatch_Pyhelper()

self_signed = True

def retrieve_assets():
    listassets = []
    output = cbw.request(
        method="GET",
        endpoint="/api/v3/servers?active=true&per_page=500",
        verify_ssl = not self_signed
    )
    for page in output: 
        listassets.extend(page.json())
        
    return listassets


def retrieve_security_issues():
    listsecurityissues = []
    output = cbw.request(
        method="GET",
        endpoint="/api/v3/security_issues?per_page=500",
        verify_ssl = not self_signed
    )
    for page in output: 
        listsecurityissues.extend(page.json())
        
    return listsecurityissues

def change_security_issue(security_issue_id, assets):
    output = Cyberwatch_Pyhelper().request(
        method="PUT",
        endpoint="/api/v3/security_issues/" + str(security_issue_id),
        body_params={'servers' : assets},
        verify_ssl = not self_signed
    )
    return next(output)

def create_security_issue(os_key,eol_date):
    output = Cyberwatch_Pyhelper().request(
    method="POST",
    endpoint="/api/v3/security_issues",
    body_params={
                  "description": "{} will be obsolete the {}".format(os_key, eol_date),
                  "level": "level_info",
                  "sid": "{}".format(os_key),
                  "title": "{} Obsolete - 6 months".format(os_key)
    },
    verify_ssl = not self_signed
    )
    return next(output)


# Regex to match the custom security issues created in this this script 
regex_security_issue = "custom-obsolete-os"

list_obsolete_security_issues = {securityissue["sid"]:(securityissue["id"],[]) for securityissue in retrieve_security_issues() if re.match(regex_security_issue,securityissue["sid"])}

# Clean all security issue (Prevent assets that have reached the EOL and those that have changed OS).
for sid in list_obsolete_security_issues.keys():
    
    sid_value = list_obsolete_security_issues[sid]
    change_security_issue(sid_value[0],[])

all_asset = [asset for asset in retrieve_assets() if asset["os"] and asset["os"]["eol"]]

today = datetime.today()

# We create a dictionary of all the asset to add 
for asset in all_asset:
    eol = asset["os"]["eol"]
    eol_date = datetime.strptime(eol,"%Y-%m-%d")
    os_key = asset["os"]["key"]
    sid_os_key = "{}-{}".format(regex_security_issue,os_key)

    # Check if eol_date_minus_6_months < today < eol_date
    if (today  >= eol_date - timedelta(days=30*6) and today < eol_date):

        # If there is not the security issue, we create it
        if(sid_os_key not in list_obsolete_security_issues.keys()):
            id = create_security_issue(sid_os_key,eol).json()["id"]
            list_obsolete_security_issues[sid_os_key] = (id,[])
            
        list_obsolete_security_issues[sid_os_key][1].append(asset["id"])

# Finally, we modify each security issue to add all the concerned assets
for sid in list_obsolete_security_issues.keys():
    sid_value = list_obsolete_security_issues[sid]
    change_security_issue(sid_value[0],sid_value[1])

