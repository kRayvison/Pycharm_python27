# coding=utf-8
import re
import gzip
import sys
import os
import subprocess
import _subprocess
import uuid

server_config = {"variables": {},
                 "spare_drives": "AEFGHIJKLMNOPQRSTUVWXYZ",
                 "upload_drive": None,
                 "project_drive": None,
                 "used_drives": None,
                 #不允许使用的盘符
                 "forbidden_drives": ["B:", "C:", "D:"],
                 "mappings": {},
                 "mounts": {},
                 "maya_file": None,
                 "maya_version": None,
                 "client_version": None,
                 "project": None,
                 "project_custom": None,
                 "project_in_maya": None,
                 "project_in_ass": None,
                 "project_in_network": 0,
                 "project_get": None,
                 "user_id": None,
                 "father_id": None,
                 "seperate_account": 0,
                 "task_id": None,
                 "renderlayer": None,
                 #获取硬件地址作为一个48位正整数。
                 "mac": "%012X" % uuid.getnode()}

class RvOs(object):
    is_win = 0
    is_linux = 0
    is_mac = 0

    if sys.platform.startswith("win"):
        os_type = "win"
        is_win = 1
        # add search path for wmic.exe
        os.environ["path"] += ";C:/WINDOWS/system32/wbem"
    elif sys.platform.startswith("linux"):
        os_type = "linux"
        is_linux = 1
    else:
        os_type = "mac"
        is_mac = 1

    @staticmethod
    def get_encode(encode_str):
        if isinstance(encode_str, unicode):
            return "unicode"
        else:
            for code in ["utf-8", sys.getfilesystemencoding(), "gb18030", "ascii", "gbk", "gb2312"]:
                try:
                    encode_str.decode(code)
                    return code
                except:
                    pass

    @staticmethod
    def str_to_unicode(encode_str):
        if isinstance(encode_str, unicode):
            return encode_str
        else:
            code = RvOs.get_encode(encode_str)
            return encode_str.decode(code)

    @staticmethod
    def get_windows_mapping():
        if RvOs.is_win:
            networks = {}
            locals = []
            all = []

            net_use = dict([re.findall(r'.+ ([a-z]:) +(.+)', i.strip(), re.I)[0]
                            for i in RvOs.run_command('net use')
                            if i.strip() if re.findall(r'.+ ([a-z]:) +(.+)',
                                                       i.strip(), re.I)])
            for i in net_use:
                net_use[i] = net_use[i].replace("Microsoft Windows Network",
                                                "").strip()

            for i in RvOs.run_command('wmic logicaldisk get deviceid,drivetype,providername'):
                if i.strip():
                    # a = re.findall(r'([a-z]:) +(\d) +(.+)?', i.strip(), re.I)
                    # print a
                    info = i.split()
                    if info[1] == "4":
                        if len(info) == 3:
                            if re.findall(r'^[\w _\-.:()\\/$]+$', info[2], re.I):
                                networks[info[0]] = info[2].replace("\\", "/")
                            else:
                                networks[info[0]] = None
                            all.append(info[0])
                        else:
                            if info[0] in net_use:
                                if os.path.exists(net_use[info[0]]):
                                    if re.findall(r'^[\w _\-.:()\\/$]+$', net_use[info[0]], re.I):
                                        networks[info[0]] = net_use[info[0]].replace("\\", "/")
                                    else:
                                        networks[info[0]] = None
                                    all.append(info[0])
                                else:
                                    # Don't know why the drive is not exists when using python to check.
                                    # Is this a network issue?
                                    # Can not reproduce this issue manually.
                                    print "%s is not exists" % (info[0])
                                    networks[info[0]] = None
                                    all.append(info[0])
                            else:
                                networks[info[0]] = None
                                all.append(info[0])

                    elif info[1] in ["3", "2"]:
                        if info[0] in server_config["forbidden_drives"]:
                            locals.append(info[0])
                        else:
                            networks[info[0]] = None
                        all.append(info[0])

        return (locals, networks, all)

    @staticmethod
    def run_command(cmd, ignore_error=None, shell=0):
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= _subprocess.STARTF_USESHOWWINDOW
        startupinfo.wShowWindow = _subprocess.SW_HIDE

        p = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                             stderr=subprocess.STDOUT, startupinfo=startupinfo,
                             shell=shell)

        while 1:
            # returns None while subprocess is running
            return_code = p.poll()
            # if return_code == 0:
            #     break
            if return_code == 1:
                if ignore_error == 1:
                    break
                else:
                    raise Exception(cmd + " was terminated for some reason.")
            elif return_code != None and return_code != 0:
                if ignore_error == 1:
                    break
                else:
                    print "exit return code is: " + str(return_code)
                    raise Exception(cmd + " was crashed for some reason.")
            line = RvOs.str_to_unicode(p.stdout.readline())

            if not line:
                break
            yield line

    @staticmethod
    def get_process_list(name):
        process_list = []
        for i in RvOs.run_command("wmic process where Caption=\"%s\" get processid" % (name)):
            if i.strip() and i.strip() not in ["ProcessId", "No Instance(s) Available."]:
                process_list.append(int(i.strip()))

        return process_list

    @staticmethod
    def get_desktop_app():
        app_names = ["qrenderbus.exe"]
        for i in app_names:
            process = RvOs.get_process_path(i)
            if process:
                return process[0]

    @staticmethod
    def get_rendercmd_exe():
        return os.path.join(RvOs.get_app_config()["installdir"], "rendercmd.exe")

    @staticmethod
    def get_app_config():
        #  os.environ["appdata"] = C:\Users\dengtao\AppData\Roaming
        #  env_ini = C:\Users\dengtao\AppData\Roaming\RenderBus\local\env.ini
        env_ini = os.path.join(os.environ["appdata"], r"RenderBus\local\env.ini")

        config = open(env_ini).readlines()
        config = dict([[j.strip() for j in i.split("=")] for i in config if "=" in i])
        return config

    @staticmethod
    def get_projects():
        cmd = RvOs.get_rendercmd_exe()
        for i in RvOs.run_command("\"%s\" -getproject" % (cmd)):
            return eval(i)

    @staticmethod
    def get_process_path(name):
        process_list = []
        for i in RvOs.run_command("wmic process where name=\"%s\" get ExecutablePath" % (name)):
            if i.strip() and i.strip() not in ["ExecutablePath", "No Instance(s) Available."]:
                process_list.append(i.strip())

        return process_list

    @staticmethod
    def get_all_child():
        parent_id = str(os.getpid())
        child = {}
        for i in RvOs.run_command('wmic process get Caption,ParentProcessId,ProcessId'):
            if i.strip():
                info = i.split()
                if info[1] == parent_id:
                    if info[0] != "WMIC.exe":
                        child[info[0]] = int(info[2])

        return child

    @staticmethod
    def kill_children():
        for i in RvOs.get_all_child().values():
            # os.kill is Available from python2.7, need another method.
            # os.kill(i, 9)
            if RvOs.is_win:
                os.system("C:\\Windows\\System32\\taskkill.exe /f /t /pid %s" % (i))
                # task_kill_exe=os.path.join(RvOs.get_app_config()["installdir"], "taskkill.exe")
                # subprocess.Popen(r'"'+task_kill_exe+'" /f /t /pid %s' % (i))

    @staticmethod
    # 超多指定时间 不能正常启动进程的 结束进程
    def timeout_command(command, timeout):
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= _subprocess.STARTF_USESHOWWINDOW
        startupinfo.wShowWindow = _subprocess.SW_HIDE

        start = time.time()
        process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, startupinfo=startupinfo, shell=False)
        while process.poll() is None:
            # print "return: " + str(process.poll())
            time.sleep(0.1)
            now = time.time()
            if (now - start) > timeout:
                # os.kill(process.pid, 9)
                if RvOs.is_win:
                    os.system("C:\\Windows\\System32\\taskkill.exe /f /t /pid %s" % (process.pid))

                return None
        return process.poll()

    @staticmethod
    def call_command(cmd, shell=0):
        return subprocess.call(cmd, shell=shell)

    @staticmethod
    def which(exe):
        if RvOs.is_win:
            cmd = "where " + exe
            print "execute: " + cmd
            for i in RvOs.run_command(cmd):
                print i

class RvPath(dict, RvOs):
    """将一个文件路径处理成一个特定功能性路径  {'mappings': {'D:': u'Z:/uploads/001A7DDA7111/D'}, 'exists': 1, 'variables': {},
    'server': u'/Z/uploads/001A7DDA7111/D/work/picture/timg.jpg',
    'source': 'D:/work/picture/timg.jpg', 'client': 'D:/work/picture/timg.jpg', 'mounts': {}}"""

    # TODO 2. we need config the maya project path from the client app
    locals, networks, all = RvOs.get_windows_mapping()

    for key in networks.keys():
        if networks[key]:
            networks[networks[key]] = key

    # assume the drive name not used in system is spare, so I can use.
    server_config["used_drives"] = all

    server_config["spare_drives"] = [i + ":" for i in server_config["spare_drives"]
                                     if i not in [j.rstrip(":") for j in all]]

    re_variable = re.compile(r'^\${?(\w+)}?', re.I)

    def __init__(self, path, exists=0, in_ass=0):
        dict.__init__(self)
        RvOs.__init__(self)
        # 定义 maya文件路径
        self["source"] = path.replace("\\", "/")
        self["client"] = self["source"]
        # 定义变量
        self["server"] = "/uploads/error"
        self["mappings"] = {}
        self["mounts"] = {}
        self["variables"] = {}
        self["exists"] = exists

        if not self["exists"]:
            if self.is_exists():
                self["exists"] = 1

        if in_ass:
            if server_config["project_custom"]:
                server_config["project_in_ass"] = server_config["project_custom"] + "/sourceimages"
            elif server_config["project_in_maya"]:
                server_config["project_in_ass"] = server_config["project_in_maya"] + "/sourceimages"
        else:
            server_config["project_in_ass"] = None

        # 获取工程目录
        self.get_server_project()

        if self["exists"]:
            if not server_config["project_in_network"] and \
                    re.findall(r"^%s" % (server_config["project_in_maya"]), self["client"], re.I):
                self.fix_project_path()
            #            self.fix_prefound_path()
            self.fix_variable_path()
            self.fix_local_path()
            self.fix_network_path()
            self.fix_unc_path()
        else:
            self.fix_variable_path()
            self.fix_project_path()

        # TODO this is some specific codes for ktcartoon
        if "/lfx_s_kuaichandian/" in self["source"].lower():
            self["server"] = self["server"].lower().replace("/lfx_s_kuaicandian/",
                                                            "/lfx_s_kuaichandian/")

        self["server"] = self["server"].replace(":", "")
        if self["server"] == "/uploads/error":
            self["server"] = "/uploads/" + self["client"].lstrip("/")
        else:
            if not self["server"].startswith("/"):
                self["server"] = "/" + self["server"]

        if self.is_win:
            # Must encode to gb18030 to save the path in cfg file on Windows.
            if isinstance(self["client"], unicode):
                self["client"] = self["client"]

            if isinstance(self["server"], unicode):
                self["server"] = self["server"]

        # 更新 映射盘符的字典
        self.update_server_config()

    def __eq__(self, other):
        return self["client"] == other["client"]

    def __hash__(self):
        return hash(self["client"])

    def __contains__(self, other):
        if isinstance(other, self.__class__):
            return other["client"] in self["client"]
        else:
            return other in self["client"]

    def __len__(self):
        return len(self["client"])

    def get_server_project(self):
        if server_config["project_in_maya"]:
            if not server_config["project_get"]:
                for i in self.networks:
                    re_project = re.compile(r'^%s' % (i), re.I)

                    if re_project.findall(server_config["project_in_maya"]):
                        project_match = i
                        project_drive = i

                        if project_match.startswith("//"):
                            project_drive = self.networks[i]

                        server_config["project"] = re_project.sub(
                            project_drive,
                            server_config["project_in_maya"])
                        server_config["project_get"] = 1
                        server_config["project_in_network"] = 1
                        server_config["project_drive"] = project_drive.rstrip("/")

                        break

    def fix_unc_path(self):
        if self["server"] == "/uploads/error":
            if self["client"].startswith("//"):
                mapping_object = re.findall(r'^(//.+?)/.+',
                                            self["client"], re.I)[0]
                drive = self.get_drive(mapping_object)
                self["mappings"][mapping_object] = drive
                self["mounts"][drive] = "/" + drive.rstrip(":")

                self["server"] = self["client"].replace(mapping_object, drive)

    def get_drive(self, mapping_object):
        for i in server_config["mappings"]:
            if self["client"].startswith(i):
                return server_config["mappings"][i]
        if not self["mappings"]:
            return self.get_new_spare_drives()

    def get_new_spare_drives(self):
        spare_drive = server_config["spare_drives"][-1]
        server_config["used_drives"].append(spare_drive)
        server_config["spare_drives"] = server_config["spare_drives"][:-1]

        return spare_drive

    def get_project_drive(self):
        if server_config["project_drive"]:
            return server_config["project_drive"]
        else:
            project_drive = self.get_new_spare_drives()
            server_config["project_drive"] = project_drive
            #            server_config["mounts"][project_drive] = "/" + project_drive.rstrip(":")
            server_config["mounts"][project_drive] = server_config["project"]
            return project_drive

    def get_upload_drive(self):
        if server_config["upload_drive"]:
            return server_config["upload_drive"]
        else:
            upload_drive = self.get_new_spare_drives()
            server_config["upload_drive"] = upload_drive
            server_config["mounts"][upload_drive] = "/" + upload_drive.rstrip(":")
            return upload_drive

    def fix_prefound_path(self):
        for i in server_config["variables"]:
            re_found = re.compile(r'^\${%s}' % (i), re.I)
            r = re_found.findall(self["client"])
            if r:
                self["variables"][i] = server_config["variables"][i]
                self["client"] = self["client"].replace(r[0], os.environ[i])
                self["server"] = self["client"].replace(os.environ[i],
                                                        server_config["variables"][i])

                return 0

        if self["server"] == "/uploads/error":
            for i in server_config["mappings"]:
                re_found = re.compile(r'^%s' % (i), re.I)
                r = re_found.findall(self["client"])
                if r:
                    self["mappings"][r[0]] = server_config["mappings"][i]
                    self["server"] = re_found.sub(server_config["mappings"][i],
                                                  self["client"])

                    return 0

        if self["server"] == "/uploads/error":
            for match_project in ["project_custom", "project_in_maya", "project_in_ass"]:
                if server_config[match_project]:
                    print match_project, server_config[match_project]
                    r = re.findall(r'^%s' % server_config[match_project],
                                   self["client"], re.I)
                    if r:
                        project_drive = self.get_project_drive()
                        # print_info2(project_drive)

                        self["server"] = self["client"].replace(r[0],
                                                                server_config["project"])

                    return 0

    def fix_variable_path(self):
        if self["server"] == "/uploads/error":
            r = self.re_variable.findall(self["client"])
            if r:
                if r[0] in os.environ:
                    print "variable %s is %s" % (r[0], os.environ[r[0]])
                else:
                    os.environ.setdefault(r[0], "")
                    print "variable  %s is dont find ,change %s" % (r[0], os.environ[r[0]])
                os.environ[r[0]].replace("\\", "/")

                if len(os.environ[r[0]].strip()) == 3:
                    self["variables"][r[0]] = os.environ[r[0]]
                    proj = "/" + os.environ[r[0]][0]
                else:
                    if ":" in os.environ[r[0]]:
                        # self["variables"][r[0]] = "/" + os.environ[r[0]].replace(":", "")
                        self["variables"][r[0]] = os.environ[r[0]]
                    else:
                        proj = os.path.basename(os.environ[r[0]])
                        self["variables"][r[0]] = "/" + proj

                self["mappings"][os.environ[r[0]]] = self["variables"][r[0]]

                if len(os.environ[r[0]].strip()) == 3:
                    self["client"] = self["client"].replace("${" + r[0] + "}",
                                                            os.environ[r[0]][:2]).replace("$" + r[0] + "",
                                                                                          os.environ[r[0]][:2])
                else:
                    self["client"] = self["client"].replace("${" + r[0] + "}",
                                                            os.environ[r[0]]).replace("$" + r[0] + "",
                                                                                      os.environ[r[0]])

                if self.is_exists():
                    self["exists"] = 1

                if len(os.environ[r[0]].strip()) == 3:
                    self["server"] = self["client"].replace(os.environ[r[0]][:2],
                                                            proj)
                else:
                    self["server"] = self["client"].replace(os.environ[r[0]],
                                                            self["variables"][r[0]])

    def fix_project_path(self):
        if self["server"] == "/uploads/error":
            for match_project in ["project_custom", "project_in_maya", "project_in_ass"]:
                if server_config[match_project]:
                    # TODO this is some specific codes for ktcartoon
                    if "/lfx_s_kuaichandian/" in self["client"].lower():
                        self["client"] = self["client"].lower().replace("/lfx_s_kuaichandian/",
                                                                        "/lfx_s_kuaicandian/")

                    path_split = self["client"].split("/")
                    for i in range(len(path_split)):
                        if server_config[match_project].endswith(":"):
                            server_config[match_project] += "/"
                        project_file = os.path.join(server_config[match_project],
                                                    *path_split[i:])
                        if os.path.exists(project_file):
                            self["client"] = project_file.replace("\\", "/")
                            self["exists"] = 1

                            r = re.findall(r'^%s' % server_config[match_project].replace("(", "\(").replace(")", "\)"),
                                           self["client"], re.I)

                            if r:
                                project_drive = self.get_project_drive()
                                # print_info2(project_drive)

                                self["mappings"]["/".join(path_split[:i])] = project_drive
                                self["server"] = self["client"].replace(r[0].rstrip("/"), server_config["project"])
                                self["mounts"][project_drive] = "/" + project_drive.strip(":")

                            return 0

    def fix_local_path(self):
        if self["server"] == "/uploads/error":
            for i in self.locals:
                r = re.findall(r'^%s' % i, self["client"], re.I)
                if r:
                    upload_drive = self.get_upload_drive()
                    self["mappings"][r[0]] = upload_drive + \
                                             "/uploads/" + server_config["mac"] + "/" + i.rstrip(":")
                    self["server"] = self["client"].replace(r[0],
                                                            self["mappings"][r[0]])

                    return 0

    def fix_network_path(self):
        if self["server"] == "/uploads/error":
            # print "the path is %s " % self["client"]
            # print type(self["client"])
            for i in self.networks:
                # print "the netwokr is %s" % i
                r = re.findall(r'^%s' % i, self["client"], re.I)
                if r:
                    if re.findall(r'\w:', self["client"], re.I):
                        drive = r[0]
                        path = self.networks[i]
                    else:
                        path = r[0]
                        drive = self.networks[i]

                    if drive.upper() in server_config["forbidden_drives"]:
                        drive_server = self.get_drive(drive)
                    else:
                        drive_server = drive

                    self["mounts"][drive_server] = "/" + drive_server.strip(":")
                    if path:
                        self["mappings"][path] = drive_server

                    self["mappings"][drive] = drive_server
                    # print "the mappings is %s" % self["mappings"]

                    for i in self["mappings"]:
                        # print type(i)
                        # print "the mappings is  %s" % i
                        new_i = i
                        if not re.findall(r'^[a-z0-9 _.:()]+$', i, re.I):
                            # new_i = i.decode("gb18030")
                            if not isinstance(i, unicode):
                                try:
                                    new_i = RvOs.str_to_unicode(i)
                                except:
                                    pass
                            else:
                                new_i = i
                        else:
                            # new_i = i.encode("gb18030")
                            if not isinstance(i, unicode):
                                try:
                                    new_i = RvOs.str_to_unicode(i)
                                except:
                                    pass
                            else:
                                new_i = i
                        if not isinstance(self["client"], unicode):
                            if i in self["client"]:
                                # print type(new_i)
                                # print type(i)
                                self["server"] = self["client"].replace(i, self["mappings"][i])
                                return 0
                        else:
                            if new_i in self["client"]:
                                # print type(new_i)
                                # print type(i)
                                self["server"] = self["client"].replace(i, self["mappings"][i])
                                return 0

                    for i in self["mounts"]:
                        if i in self["client"]:
                            self["server"] = self["client"].replace(i, self["mounts"][i])

                            return 0

    def update_server_config(self):
        for type_i in ["variables", "mappings", "mounts"]:
            for i in self[type_i]:
                if i:
                    if i not in server_config[type_i]:
                        server_config[type_i][i] = self[type_i][i]

        server_config["mounts"] = dict([(self.encode(i[0]), self.encode(i[1]))
                                        for i in server_config["mounts"].items()])

    def encode(self, string, code="utf-8"):
        if isinstance(string, unicode):
            return string.encode(code)
        else:
            return string

    @property
    def server_long_path(self):
        path = self["client"]

        if self["exists"]:
            if self.is_win:
                for i in self["mappings"].keys():
                    if isinstance(i, unicode):
                        self["mappings"][i.encode("utf-8")] = self["mappings"].pop(i)

                        #        path = "".join([self.options["server_home"],
                        #            self.options["user_home"], self.options["project_home"],
                        #            self["server"]])

                for i in self["mappings"]:
                    if RvOs.str_to_unicode(self["client"]).encode("utf-8").startswith(i):
                        path = RvOs.str_to_unicode(self["client"]).encode("utf-8").replace(i,
                                                                                           self["mappings"][i])
                        break

            #            key = self["mappings"].keys()[0]
            #            path = self["client"].replace(key, self["mappings"][key])

            if self.is_win:
                if isinstance(path, unicode):
                    return path.encode("utf-8")
            return path

    def is_file(self):
        return os.path.isfile(self["client"])

    def is_exists(self):
        if ":" in os.path.basename(self["client"]):
            return not os.system("dir %s" % self["client"].replace("/", "\\"))
        else:
            return os.path.exists(self["client"])

    def is_dir(self):
        return os.path.isdir(self["client"])

class FileSequence():

    NUMBER_PATTERN = re.compile("([0-9]+)")
    # NUMBER_PATTERN2 = re.compile("([0-9]+)")
    # NUMBER_PATTERN2 = re.compile("(?<=\.)([0-9]+)(?=\.)")
    # NUMBER_PATTERN2 = re.compile("([0-9]+)(?=[\._])")
    NUMBER_PATTERN2 = re.compile("(-?[0-9]+)(?![a-zA-Z\d])")
    PADDING_PATTERN = re.compile("(#+)")

    def __init__(self, path="", head="", tail="", start=0, end=0, padding=0,
                 missing=[]):
        self.path = path.replace("\\", "/")
        self.head = head
        self.tail = tail
        self.start = start
        self.end = end
        self.padding = padding
        self.missing = missing

    @classmethod
    def find(cls, search_path, ext=None, actual_frange=None):
        my_sequences, my_others = [], []
        path_group = {}
        if isinstance(search_path, list):
            for i in search_path:
                folder = os.path.dirname(i).replace("\\", "/")
                path_group.setdefault(folder, [])
                path_group[folder].append(os.path.basename(i))

class ArnoldNode(dict):

    NUMBER_PATTERN = re.compile(r'[+-]?\d*.?\d*$')

    def __init__(self, type):
        dict.__init__(self)
        self["type"] = type

    def format(self, style="katana"):
        for i in self:
            if i == "type":
                pass
            elif i == "name":
                self[i] = self[i][0]
            else:
                if len(self[i]) == 1:
                    self[i] = self.covert_str_to_real_type(self[i][0])
                else:
                    self[i] = [self.covert_str_to_real_type(j)
                        for j in self[i]]

        if style == "katana":
            self.format_to_katana_type()

    def covert_str_to_real_type(self, s):
        if self.NUMBER_PATTERN.match(s):
            return eval(s)
        elif s == "on":
            return True
        elif s == "off":
            return False
        else:
            return s.strip("\"")

    def format_to_katana_type(self):
        if self["type"] == "MayaFile":
            self["type"] = "image"

        self["parameters"] = {}

        for i in self.keys():
            if i not in ["name", "type", "parameters"]:
                self["parameters"][i] = self[i]
                self.pop(i)

        self["connections"] = {}

class AssFile(list):
    DATE_PATTERN = re.compile("^### exported: +(.+)")
    ARNOLD_PATTERN = re.compile("^### from: +(.+)")
    APP_PATTERN = re.compile("^### host app: +(.+)")
    TYPE_PATTERN = re.compile("^[a-zA-Z].+")

    def __init__(self, ass_file=None, node_list=[]):
        self.is_gzip = 0
        if ass_file:
            if ass_file.endswith(".gz"):
                self.is_gzip = 1

        if node_list:
            self += node_list
            for i in self:
                if "filename" in i:
                    if not i["filename"][0].endswith('"'):
                        i["filename"] = [i["filename"][0] + '"']
        else:
            self.ass_file = ass_file
            self.current_node = {}

            self.get_nodes()

    def get_files_from_ass(self, ass_file=None):
        if ass_file:
            ass_nodes = AssFile(ass_file)
        else:
            ass_nodes = self

        texture = [RvPath(eval(i["filename"][0]), in_ass=1)
                   for i in ass_nodes.filter("MayaFile")]

        texture += [RvPath(eval(i["filename"][0]), in_ass=1)
                    for i in ass_nodes.filter("image")]

        texture += [RvPath(eval(i["filename"][0]), in_ass=1)
                    for i in ass_nodes.filter("procedural")
                    if "filename" in i if eval(i["filename"][0])]

        for i in ass_nodes.filter("procedural"):
            if "G_assetsPath" in i:
                if eval(i["G_assetsPath"][0]):
                    texture += [RvPath(eval(i["G_assetsPath"][0]), in_ass=1)]
                    break
        for i in ass_nodes.filter("include"):
            texture += [RvPath(eval(i["include"][0]), in_ass=1)]

        ass = list(set([RvPath(eval(i["dso"][0]))
                        for i in ass_nodes.filter("procedural")
                        if "dso" in i if eval(i["dso"][0])]))
        ass += list(set([RvPath(eval(i["filename"][0]))
                         for i in ass_nodes.filter("procedural")
                         if "filename" in i if eval(i["filename"][0]) if
                         eval(i["filename"][0]).lower().endswith(".ass")]))
        ass += list(set([RvPath(eval(i["include"][0]))
                         for i in ass_nodes.filter("include") if eval(i["include"][0]).lower().endswith(".ass")]))

        #sequences, others = FileSequence.find([i["client"] for i in ass])
        #analyze_ass = []
        # for i in sequences:
        #     analyze_ass.append(RvPath(i.startFileName))
        # for i in others:
        #     analyze_ass.append(RvPath(i))
        #
        # for i in analyze_ass:
        #     if i["exists"]:
        #         texture += self.get_files_from_ass(i["client"])

        return [i for i in set(texture + ass)]

    def get_nodes(self):
        if self.is_gzip:
            open_obj = gzip.open(self.ass_file)
        else:
            open_obj = open(self.ass_file)
        for line in open_obj:
            line = line.strip()
            if line:
                if line.startswith('#'):
                    pass
                elif self.TYPE_PATTERN.findall(line):

                    if self.current_node:
                        group = line.split()

                        if len(group) == 1:
                            pass
                        elif len(group) > 1 and group[1].startswith("\""):
                            self.current_node[group[0]] = [" ".join(group[1:])]
                        else:
                            self.current_node[group[0]] = group[1:]
                    else:
                        line = [i for i in line.split() if i not in ["{", "}"]]

                        if len(line) == 1:

                            self.current_node = ArnoldNode(line[0])
                        else:
                            # print line
                            # procedural { name cube dso "R:/filmServe/1019_JA_JZZ/VFX/assets/CGassets/Sets/SkyCity/Model/Publish/JZZ_PalaceBridgeSETS_mod_LOD150.ass"
                            self.current_node = ArnoldNode(line[0])

                            for index, i in enumerate(line):

                                if index % 2:

                                    if index < len(line):
                                        self.current_node[line[index - 1]] = [line[index]]
                            self.append(self.current_node)

                if "}" in line:
                    self.append(self.current_node)
                    # print self.current_node
                    self.current_node = {}

    def filter(self, type):
        # 'MayaShadingEngine'
        if type == "shader":
            nodes = [i for i in self if
                     i["type"] in ['MayaFile', 'MayaNormalDisplacement',
                                   'ginstance', 'lambert', 'mayaBump2D',
                                   'sky', 'standard', ] or i["type"].startswith("of_")]
        else:
            nodes = [i for i in self if "type" in i if i["type"] == type]

        if nodes:
            return AssFile(node_list=nodes)
        else:
            return []

    def get_names(self):
        return set([i["name"][0] for i in self])

    def get_types(self):
        return set([i["type"] for i in self])

    def format(self, style="katana"):
        for i in self:
            i.format(style)

        for i in self:
            for j in i["parameters"].keys():
                if i["parameters"][j] in [k["name"] for k in self]:
                    i["connections"][j] = i["parameters"][j]
                    i["parameters"].pop(j)
                    
if __name__ == '__main__':
    assb=AssFile(r'D:\test\ass_test\scenes\testgz.ass.gz')
    aaa = assb.get_files_from_ass()
    for i in aaa:
        print (i)

    #print (assb)
