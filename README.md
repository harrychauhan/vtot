# vtot
<strong>Python VirusTotal API Implementation</strong>

<strong>Usage</strong>

<strong>If script "virustotal.py" is run directly:</strong>

1) python virustotal.py -h
2) python virustotal.py -v
3) python virustotal.py -k [apikey] -l[hash] -l[hash] -l[hash] -l[hash]

   (Your api key and max of 4 file hashes. You can also include local filepath.)
    
<strong>If script is used as a module:</strong>

import vtot.virustotal

api = "[apikey]"

hashlist = ["filehash", "filehash","filehash","filehash"]   # You can also include local filepath

x = vtot.virustotal

resp=x.vtotal(api, hashlist)

print(resp)
