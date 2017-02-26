#!/usr/bin/python

"""script to run tcpdump with user-provided options"""

import os
import sys
import time
import signal
import tempfile
import subprocess


def parse_args():
  #Store the args/inputs in dictionary
  keys = sys.argv[1::2]
  values = sys.argv[2::2]
  d = dict(zip(keys, values))
  return d


def unique_file(pfix_half):
  #create a folder to locate dump files
  dir_path = '/var/log/tcpdump_log'
  if not os.path.exists(dir_path):
    os.makedirs(dir_path)

  full_path = dir_path+'/'
  pfix = pfix_half+'_dump-'
  sfix = '.read'
  fdx = tempfile.mkstemp(prefix=pfix, suffix=sfix, dir=full_path)
  return fdx


def disp_status(pcapfile, readfile):
  print "status \"~~~~~~~~~~~~~~~~~~~~~~~~~~~\""
  print "status \"~~~~~~~~~~~~~~~~~~~~~~~~~~~\""
  print "status \"~~~~~~~~~~~~~~~~~~~~~~~~~~~\""
  print "status \"\ntcpdump files created:\""
  print "status \"%s\"" % pcapfile
  print "status \"%s \"" % readfile


def filename_prefix(d):
  #Get the prefix for the file name
  if 'protocol' in d:
    pfix_half = d.get('protocol')
  else:
    if 'port' in d and 'interface' in d:
      pfix_half = 'port-intf'
    elif 'port' in d:
      pfix_half = 'port'
    elif 'interface' in d:
      pfix_half = 'intf'
    else:
      pfix_half = 'multi-arg'

  return pfix_half


def user_input_flags(d):
  #Reqd for file name. Not for flags
  if 'protocol' in d:
    d.pop('protocol')
    
  # flag = 'port 53'
  if 'port' in d:
    tmp = d.get('port')
    d['port'] = 'port '+tmp

  flag_list = d.values()

  #interface = '-i eth0'
  intf = d.get('interface')
  if intf in flag_list:
    intf_idx = flag_list.index(intf)
    flag_list.insert(intf_idx, '-i')

  return flag_list


def start_tcpdump(d):
  #Get the duration of capture
  duration = int(d.pop('duration'))
  
  pfix_half = filename_prefix(d)

  #Get the unique file name
  fdx = unique_file(pfix_half)
  fd = fdx[0]
  readfile = fdx[1]
  pcapfile = readfile.replace(".read", ".pcap")  

  #Get the tcpdump action flags given by user
  user_flags = user_input_flags(d)

  #List of flags for tcpdump
  full_flags = ['tcpdump', '-U', '-w', pcapfile]
  full_flags.extend(user_flags)

  #EXECUTE TCPDUMP
  ps_dump = subprocess.Popen(full_flags)
  time.sleep(duration)
  ps_dump.send_signal(signal.SIGINT)

  #human readable format
  #tcpdump -qns 0 -X -r myfile
  f = os.fdopen(fd, 'w')
  ps_read = subprocess.Popen(['tcpdump', '-qns', '0', '-X', '-r', pcapfile], stdout=subprocess.PIPE)
  r_output = ps_read.communicate()[0]
  f.write(r_output)
  f.close()

  #display the file locations
  disp_status(pcapfile, readfile)


def execute_process():
  dict_args = parse_args()
  #send the tcpdump flags
  start_tcpdump(dict_args)

#start
execute_process()
