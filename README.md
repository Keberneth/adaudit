### The PS5 script will not be developted anymore. The PS7 is a converted version of the PS5 script and have more adudit functions and improved reports
<br><br>

## Active Directory Assessment Overview
This script performs an assessment of Active Directory configuration, security posture, and operational health.  
The output is intended to provide visibility into potential risks, misconfigurations, and improvement areas.
<br><br>

## Risk Report
The management report is an HTML file that provides a more presentable summary of the audit, including an overall security score.<br>
The further a finding deviates from the defined baseline, the higher the risk score becomes. For example, Critical risks start at 12 points, but both criticality and score increase the further the risk is from the baseline.<br>
If the KRBTGT password has not been changed in 180 days, it is considered a Critical risk (12 points). However, if it has not been changed in 2000 days, the score increases to 31 points.<br>
Similarly, if there are many accounts that have not been used for a long time, the risk score increases as the number of inactive accounts grows.<br>
This scoring model helps pinpoint and prioritize security issues and highlights how neglected certain areas are. A finding with low initial criticality can become high or Critical if it deviates far enough from the baseline value.
<br><br>


### IMPORTANT
All findings must be evaluated in the context of:<br>
- Organizational and regulatory requirements<br>
- Internal security policies and approved exceptions<br>
- Established operational practices and business constraints<br>
- Business requirements<br>
<br>
The presence of a finding does not automatically indicate a security issue.  <br>
Results should be reviewed, validated, and prioritized according to the organization’s risk management process.<br>
<br>

### Purpose
This script is designed to support informed decision-making and continuous improvement of Active Directory security and operational hygiene.
<br><br>

# adaudit
This PowerShell script is designed to conduct a comprehensive audit of Microsoft Active Directory, focusing on identifying common security vulnerabilities and weaknesses. Its execution facilitates the pinpointing of critical areas that require reinforcement, thereby fortifying your infrastructure against prevalent tactics used in lateral movement or privilege escalation attacks targeting Active Directory.
```
<br><br>
### Original script created by: <br>
_____ ____     _____       _ _ _
|  _  |    \   |  _  |_ _ _| |_| |_
|     |  |  |  |     | | | . | |  _|
|__|__|____/   |__|__|___|___|_|_|
                 by phillips321
```
<br>
https://github.com/phillips321/adaudit


<br><br>

# Dependencies
Copy the ADAudit folder to the DC Server or a server with the RSAT tools installed and can manage active directory. The account running the script need to be Domain Admin to run the full audit. <br><br>

Download NuGet and DSInternals modules from PowerShell Gallery before using any audit scripts and place in the same folder as the script.<br>
https://www.powershellgallery.com/packages/NuGet/<br>
https://www.powershellgallery.com/packages/DSInternals/<br>
Chose Manual Download. You will get two .nuplkg files. Plase them in the ADAudit folder.<br><br>

To install the required modules, run the powershell script AdAudit-Run.ps1 and chose option 2 for offline installation.<br><br>
For PS7 version you have offline installation in GUI script or run InstallDeps.ps1 in PowerShell 7 and place script in same folder as the .nuplkg files
<br><br>
