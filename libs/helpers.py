
from termcolor import cprint 

def usage():
  
  print("""

./hrafna.py [mode] [scan.yaml]


Modes

  scan   -> execute a scan and record results 
            can be stopped and continued if need be
  
  reset  -> reset that scan from the config
  
  report -> show results from a scan 
  
  
  
  """)


def welcome(version):
  
  cprint("""
  
   __   __  ______    _______  _______  __    _  _______ 
  |  | |  ||    _ |  |   _   ||       ||  |  | ||   _   |
  |  |_|  ||   | ||  |  |_|  ||    ___||   |_| ||  |_|  |
  |       ||   |_||_ |       ||   |___ |       ||       |
  |       ||    __  ||       ||    ___||  _    ||       |
  |   _   ||   |  | ||   _   ||   |    | | |   ||   _   |
  |__| |__||___|  |_||__| |__||___|    |_|  |__||__| |__|
  
      log4j-scanner for the masses
      CVE-2021-44228
    
      version: %s
  
  """ % version, "green")
