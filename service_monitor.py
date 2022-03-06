import datetime
import platform
from datetime import time
from time import gmtime, strftime, sleep
import psutil
import psutil as ps
import hashlib
import os
from os import path
import portalocker
import json
import threading
from threading import Thread, Lock

name_list = 'serviceList.json'
name_log = 'Status_log.txt'

"""
security class
"""
mutex = Lock()

"""
this class is responsible for security our files.
the security process has two levels
first - while the program running no one will be allowed to gain access to any of our files.
second - when the program exit, the files will get a signature, 
this signature will be checked to ensure that no one touched the files 
"""


class security:
    """
    the init part
    """

    def __init__(self, curr_os: str):
        try:
            if not path.exists(name_list):  # if the file does not exists
                self.service_list = self.first_time(name_list)
                dict_init = {"time": ["running services"]}
                json.dump(dict_init, self.service_list, indent=4)
            else:  # if the file exists then we should check it
                self.authorized_file(name_list)
                self.authorized_file(name_log)
                if not os.path.exists(name_list):#if the file removed then create it
                    self.service_list = self.first_time(name_list)
                    dict_init = {"time": ["running services"]}
                    json.dump(dict_init, self.service_list, indent=4)
                else:
                    self.service_list = open(name_list, 'r+')
            self.status_log = open(name_log, 'a+')
            self.curr_os = curr_os
            self.lock_file(name_log)  # lock the files
            self.lock_file(name_list)
        except:
            print("[-] there was a problem while creating the log files\nplese check this out and try again.\n")
            exit(1)

    def first_time(self, filename):
        try:
            file_1 = open(filename, 'a+')  # just create the file
            file_1.close()
            file = open(filename, 'r+')
            return file  # return fd of the file
        except:
            print("[-] there was a problem while opening the files, please check this out and try again.")
            exit(1)

    """
    this function removes the lock of of the file
    """

    def unlock_file(self, filename):
        if filename == name_list:
            portalocker.unlock(self.service_list)
        else:
            portalocker.unlock(self.status_log)

    """
    this function add an exclusive lock to the received file
    this process guarantee that no other program can get access to this locked file
    """

    def lock_file(self, filename):
        if filename == name_list:
            try:
                portalocker.lock(self.service_list, portalocker.LockFlags.EXCLUSIVE)
            except:
                print("[-] problem with lock the file {0} please check this out and try again\n".format(filename))
        else:
            try:
                portalocker.lock(self.status_log, portalocker.LockFlags.EXCLUSIVE)
            except:
                print("[-] problem with lock the file {0} please check this out and try again\n".format(filename))

    """
    if a security risk were detected then this handler will get a call
    """

    def handle_security(self, filename: str , fd_old_file):
        print("file {0} may be in a security risk, please choose what U want to do:".format(filename))
        while True:
            try:
                rec = int(input("press 1 - remove the suspicious file and Exit this program\npress 2 - remove the suspicious "
                                "files and proceed\npress 3 - make a copy of the suspicious file and start the "
                                "program with "
                                "new file\n"))
                break
            except:
                print("wrong input!")
        try:
            while True:
                if rec == 1:
                    fd_old_file.close()
                    os.remove(filename)
                    current_system_pid = os.getpid()  # close the program
                    ThisSystem = psutil.Process(current_system_pid)
                    ThisSystem.terminate()
                elif rec == 2:
                    fd_old_file.close()
                    os.remove(filename)
                    return
                elif rec == 3:
                    with open("backup_{0}_{1}".format(strftime("%S", gmtime()),filename), 'a+') as copy:
                        with open(filename , "r+") as file:
                            for line in file.readlines():
                                copy.write(line)
                            file.close()
                    fd_old_file.close()
                    os.remove(filename)
                    return
                rec = int(
                    input("press 1 - remove the suspicious file and Exit this program\npress 2 - remove the suspicious "
                          "files and proceed\npress 3 - make a copy of the suspicious file and start the program with "
                          "new file\n"))
        except:
            print("problem with handler")
    """
    this function returns the checksum of the received file
    if the file changed then the checksum will be different
    we are using hashlib module for this process
    """

    def get_curr_checksum(self, filename: str):
        with open(filename, 'rb') as curr:
            content = curr.read()
            curr.close()
            md = hashlib.md5()
            md.update(content)
            return md.hexdigest()

    """
    this function invoke whenever the this program starting to run
    the aim of this function is to authorized this file, i.e no one changed this file
    """

    def authorized_file(self, filename: str):
        with open(filename, 'r+') as file:
            old_c = file.readlines()[-1]  # get the old checksum
            self.remove_signature(filename, file)  # remove the signature of the file for knowing the real checksum
            new_c = self.get_curr_checksum(filename)
            if old_c == new_c:
                return
            else:
                self.handle_security(filename, file)

    """
    this function adds to the recived file a signature 
    the signature is the checksum of the file
    """

    def add_signature(self, filename: str):
        sign = self.get_curr_checksum(filename)
        if filename == name_list:
            with open(name_list, 'a+') as curr:
                curr.write('\n' + sign)
                curr.close()
        else:
            with open(name_log, 'a+') as curr:
                curr.write('\n' + sign)
                curr.close()

    """
    this function removes the checksum of the received file
    """

    def remove_signature(self, filename , fd_old_file):
        with open(filename, 'r+') as curr:
            lines = curr.readlines()
            with open("copy - {}".format(filename), 'a+') as copy:  # creates a copy file
                for line in range(0, len(lines) - 2):  # we suppose to copy all the lines except the last two lines
                    copy.write(lines[line])
                if filename == name_list:
                    copy.write('}')
                copy.close()
            curr.close()
            fd_old_file.close()
            try:
                os.remove(filename)
                os.rename("copy - {}".format(filename), filename)
            except:
                pass



    def secure_exit(self, operation: str):
        if operation == 'exit':
            mutex.acquire()
            self.unlock_file(name_list)
            self.unlock_file(name_log)
            self.service_list.close()
            self.status_log.close()
            self.add_signature(name_list)
            self.add_signature(name_log)
            print("Goodbye")
            current_system_pid = os.getpid()  # close the program
            ThisSystem = psutil.Process(current_system_pid)
            ThisSystem.terminate()
        else:
            self.unlock_file(name_list)
            self.unlock_file(name_log)
            self.service_list.close()
            self.status_log.close()
            self.add_signature(name_list)
            self.add_signature(name_log)
            return


"""
this class is for the hand mode

"""


class hand:
    def __init__(self, curr_os):
        self.curr_os = curr_os
        self.secure = security(self.curr_os)
        self.service_dict = self.get_dict()

    def start(self):
        while True:
            while True:
                try:
                    rec = int(input("press 1 - to watch all the valid dates\npress 2 - to compare between two "
                                    "dates\npress 3 - to return to the main menu\npress 0 - to Exit this program"))
                    break
                except:
                    print("Wrong input!\n")
            if rec == 1:
                print(self.service_dict.keys())
            elif rec == 2:
                key_a, date_a, time_a = self.get_date_user('First')
                key_b, date_b, time_b = self.get_date_user('Second')
                key_a, key_b = self.sort_by_date(key_a, key_b, date_a, time_a, date_b, time_b)
                self.show_diff(key_a, self.service_dict[key_a], key_b, self.service_dict[key_b])
            elif rec == 3:
                self.secure.secure_exit("return")
                return
            elif rec == 0:
                self.secure.secure_exit("exit")
            else:
                print("wrong input, try again!\n")

    def get_dict(self) -> dict:
        self.secure.service_list.seek(0)
        try:
            data = json.load(self.secure.service_list)
        except:
            print("[-] there is a problem with the Json file\nthis problem probably caused by unexpected exit which "
                  "destroyed this file\nplease remove the json file and try again.")
            return dict()
        return data

    def get_date_user(self, number: str):
        while True:
            try:
                date = input("{0} date\nEnter date in YYYY-MM-DD format\n".format(number))
                year, month, day = map(str, date.split('-'))
                date = datetime.date(int(year), int(month), int(day))
                time = input("Enter time in HH-MM-SS format\n")
                hour, minute, second = map(str, time.split(':'))
                time = datetime.time(int(hour), int(minute), int(second))

                ans = "{0} {1}".format(date, time)
                if self.is_valid_date(ans):
                    return ans, date, time
                else:
                    print("this date does not exists\nplease try again")
            except:
                print("Wrong input, Try again")

    def is_valid_date(self, date):
        return date in self.service_dict

    def sort_by_date(self, key_a, key_b, date_a, time_a, date_b, time_b):
        if date_a == date_b:
            if time_a < time_b:
                return key_a, key_b
            else:
                return key_b, key_a
        elif date_a < date_b:
            return key_a, key_b
        else:
            return key_b, key_a

    def show_diff(self, date_a: str, first: list, date_b: str, second: list):
        found = False
        for i in first:
            if i not in second:
                found= True
                print("[+] service {0}: earlier at {1} still ran, but in the later sample {2} it did not run".format(i, date_a, date_b))

        for i in second:
            if i not in first:
                found = True
                print("[+] service {0}: earlier at {1} did not run, but in the later sample {2} it did run".format(i, date_a, date_b))
        if not found:
            print("nothing different\n")

"""
monitor class
"""


class monitor:

    def __init__(self, curr_os, x_time: float):
        self.curr_os = curr_os
        self.x_time = x_time
        self.secure = security(self.curr_os)
        t1 = threading.Thread(target=self.background_input)
        t1.start()

    def background_input(self):
        while True:
            rec = input("\npress 0 -- if U want to exit this program safely\n")
            if rec == '0':
                self.secure.secure_exit("exit")

    def start(self):
        if curr_os == 'windows':
            self.windows()
        else:
            self.linux()

    """
    status_log is a txt file
    """

    def write_to_status_log(self, status: str):
        self.secure.status_log.write(status)
        self.secure.status_log.tell()

    def write_to_service_list(self, log: dict):
        mutex.acquire()  # get the mutex --> this is a critical section, becouse there is a thread that may close the
        # files at any moment
        self.secure.service_list.seek(0)  # go to the start of the file
        try:
            data = json.load(self.secure.service_list)  # save the old json into data
            data.update(log)  # update the data with the received log
            self.secure.service_list.seek(0)  # go to the start of the file again
            json.dump(data, self.secure.service_list, indent=4)  # dump the updated data into the json
            mutex.release()  # now the mutex can release
        except:
            print("[-] there is a problem with the Json file\nthis problem probably caused by unexpected exit which "
                  "destroyed this file\nplease remove the json file and try again.")
            mutex.release()

    """
    this function gets 2 dict and checks if they are different, if so -> tells what exactly are the differences
    """

    def diff(self, old_dict: dict, old_time, new_dict: dict, new_time):
        for i in old_dict[old_time]:
            if i not in new_dict[new_time]:
                msg = "[-] {0} -- service {1} is no longer running\n".format(strftime("%Y-%m-%d %H:%M:%S", gmtime()), i)
                self.write_to_status_log(msg)
                print(msg)
                print("press 0 -- if U want to exit this program safely\n")

        for i in new_dict[new_time]:
            if i not in old_dict[old_time]:
                msg = "[+] {0} -- service {1} just started\n".format(strftime("%Y-%m-%d %H:%M:%S", gmtime()), i)
                self.write_to_status_log(msg)
                print(msg)
                print("press 0 -- if U want to exit this program safely\n")


    def windows(self):
        old_dict_services = dict()
        new_dict_services = dict()
        old_time = ""
        flag = True  # if its the first loop
        while True:
            new_time = strftime("%Y-%m-%d %H:%M:%S", gmtime())
            curr_set = []
            for service in ps.win_service_iter():
                if service.status() == "running":
                    curr_set.append(service.name())
            new_dict_services[new_time] = curr_set
            self.write_to_service_list(new_dict_services)
            if flag:
                old_time = new_time
                old_dict_services = new_dict_services
                sleep(self.x_time)
                flag = False
                continue
            self.diff(old_dict_services, old_time, new_dict_services, new_time)
            old_time = new_time
            old_dict_services = new_dict_services
            sleep(self.x_time)

    def linux(self):
        old_dict_services = dict()
        new_dict_services = dict()
        old_time = ""
        flag = True  # if its the first loop
        while True:
            new_time = strftime("%Y-%m-%d %H:%M:%S", gmtime())
            curr_set = []
            for service in ps.process_iter():
                if service.status() == "running":
                    curr_set.append(service.name())
            new_dict_services[new_time] = curr_set
            self.write_to_service_list(new_dict_services)
            if flag:
                old_time = new_time
                old_dict_services = new_dict_services
                sleep(self.x_time)
                flag = False
                continue
            self.diff(old_dict_services, old_time, new_dict_services, new_time)
            old_time = new_time
            old_dict_services = new_dict_services
            sleep(self.x_time)


"""
main driver
"""

if __name__ == '__main__':
    curr_os = platform.system().lower()
    print("welcome to our services monitor\nyour current system is {0}".format(curr_os))
    while True:
        try:
            rec = int(input("press...\n1 for Monitor Mode\n2 for Hand Mode\n0 for Exit this program\n"))
            break
        except:
            pass
    while rec != 0:
        if rec == 1:
            while True:
                try:
                    sec = int(input("please enter a period of time in seconds to monitor\n"))
                    break
                except:
                    print("Wrong input!")
            mode = monitor(curr_os, sec)
            mode.start()


        elif rec == 2:
            mode = hand(curr_os)
            mode.start()
        else:
            print("Wrong Input!")
        try:
            rec = int(input("press...\n1 for Monitor Mode\n2 for Hand Mode\n0 for Exit this program\n"))
        except:
            pass
    print("GoodBye!")
