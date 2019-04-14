######################################################
# VirusTotal API Implementation
# No License. Free to use
######################################################

__author__ = "Harry Chauhan"
__maintainer__ = "Harry Chauhan"
__version__ = "1.0.0"


import os
import sys
import requests
import getopt
import queue
import json


q = queue.Queue(maxsize=4)


def usage():
    print("Max arguments: 5")
    print("API Key (-k) and at least 1 and upto 4 file hash values or file path (-l)")
    print("Usage: " + sys.argv[0] + " [OPTIONS]")
    print("Exmaple: " + sys.argv[0] + " " + \
    "-k [api key] -l [value one] -l [value two] -l [value three] -l [value four]")
    return


def newthread(key, q):           # This is the worker. Outputs server response to response.
    url = "https://www.virustotal.com/vtapi/v2/file/report"
    jsonresp=[]
    try:
        while not q.empty():
            filehash=q.get()
            print("Requesting filehash: " +filehash)
            params = {"apikey": key, "resource": filehash}
            response = requests.get(url, params=params)
            if response.status_code == 200:
                print("Request successful")
                jsonresp.append(response.json())
            else:
                print("Request not successful. Status code: ", response.status_code)
                jsonresp=None
            q.task_done()
        return jsonresp
    except requests.exceptions.ConnectionError as e:
        print("Request for filehash '" +filehash+ "' failed")
        print(e.args)
        return None
    except requests.exceptions.HTTPError as e:
        print("Request for filehash '" +filehash+ "' failed")
        print(e.args)
        return None
    except requests.exceptions.Timeout as e:
        print("Request for filehash '" +filehash+ "' failed")
        print(e.args)
        return None
    except KeyboardInterrupt as e:
        print("Request for filehash '" +filehash+ "' failed")
        print(e.args)
        return None
    except requests.exceptions.RequestException as e:
        print("Request for filehash '" +filehash+ "' failed")
        print(e.args)
        return None


def checkparameters(key, hashlist):         # checks the number of parameters. Returns True or False.
    if (len(hashlist) > 4) or (len(hashlist) < 1):
        print("Incorrect number of parameters in list. Maximum 4, Minimum 1.")
        return False
    elif not key:
        print("API key not passed")
        return False
    else:
        return True


def vtotal(key, hashlist):
    jsonresp=[]
    if checkparameters(key, hashlist):          # if checkparameters() returns true
        for i in range(len(hashlist)):          # loop through hashlist
            if "\\" in hashlist[i]:
                try:
                    if os.path.isfile(hashlist[i]):   # check if any of the parameter in hashlist[] is a file path
                        filehash = hashlib.md5(open(hashlist[i], 'rb').read()).hexdigest()  # get the file hash
                        q.put(filehash)
                    elif not os.path.isfile(hashlist[i]):       # if parameter is not a legit file path
                        print("Invalid file parameter: " + hashlist[i])      # don't do anything
                        pass
                except IOError as e:
                    print(e.errno)
                    pass
                except EOFError as e:
                    print(e.args)
                    pass
                except ValueError as e:
                    print(e.args)
                    pass
            else:
                q.put(hashlist[i])
        jsonresp=newthread(key, q)
        return jsonresp
    else:
        return None


def main():                         # executed when script is run directly
    hashlist = []                   # function accepts command line parameters
    jsonresp = []                   
    try:
        opts, args = getopt.getopt(sys.argv[1:], "k:l:l:l:l:hv", )
        if len(opts) == 1:
            if opts[0][0] == "-h":
                usage()
            elif opts[0][0] == "-v":
                print("vtot version: " + __version__)
                sys.exit(0)
            elif opts[0][0] == "-k":
                print("No file hash or file path supplied")
                sys.exit(0)
        elif (len(opts) > 1) and (len(opts) < 6):
            for x, y in opts:
                if x == "-k":
                    key = y
                if x == "-l":
                    hashlist.append(y)
            jsonresp=vtotal(key, hashlist)
            print("JSON Response:")
            print(jsonresp)
        else:
            print("Incorrect number of arguments")
            usage()
    except getopt.GetoptError as err:
        print(err)  # will print errors
        sys.exit(-1)


if __name__=='__main__':
    main()
    sys.exit(0)






