# Installation of the software and code
Execution of the script requires the installation of python 2.6 or higher.
Python 2.6 or higher can be downloaded from this link.
https://www.python.org/download/releases/2.6/
The code to run on python can be downloaded from our repository. The link to download the code is:
https://github.com/rishikesh-sahay/supercloud/blob/master/simple_switch_isp.py
We excuted the script on the RYU SDN controller, but other SDN controller can also be used to execute.
RYU can be downloaded and install from the GitHub repository: https://github.com/osrg/ryu
Instructions are provided on the repository to install the RYU.

##### Libraries to import to execute the code.
It requires to import httplib, urlparse, etree and ElementTree
User needs to download the policy files which contain the security policies. Policy files can be downloaded from our repository. HHowever, user can also write his own policies following the example given in our policy file.
Link to download the policy file is:
script can be executed with the command:
ryu-manager simple_switch_isp.py
