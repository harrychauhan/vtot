# vtot
Python VirusTotal API Implementation

Usage
If script "virustotal.py" is run directly:
1) python virustotal.py -h
2) python virustotal.py -v
3) python virustotal.py -k [apikey] -l[hash] -l[hash] -l[hash] -l[hash]
    (Your api key and max of 4 file hashes. You can also include local filepath.)
    
If script is used a module

import vtot.virustotal

api = "[apikey]"
list = ["filehash", "filehash","filehash","filehash"]   # You can also include local filepath

x = vtot.virustotal
resp=x.vtotal(api, list)
print(resp)
