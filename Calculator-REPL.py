#!/usr/bin/env python
# -*- coding:utf8 -*-


import inspect
import shlex
import signal
import math
import sys

from cmd import Cmd


def singal_handler(signal, frame):
    raise sys.exit(0)


def split(func):
    def result(self, line):
        argvalues = shlex.split(line)
        argnames = inspect.getargspec(func).args
        argcount = len(argnames) - 1
        if len(argvalues) != argcount:
            print "[Fail] Need exactly %d args" % argcount
            return
        return func(self, *argvalues)
    return result


class ScientificCalcREPL(Cmd):

    prompt = "[Scientific >>] "

    @split
    def do_pow(self, a, b):
        print (pow(int(a), int(b)))

    @split
    def do_factorial(self, a):
        print math.factorial(int(a))

    def do_quit(self, args):
        return True


class CalcREPL(Cmd):

    prompt = "[Basic >>] "

    def do_quit(self, args):
        """Quits the program."""
        raise SystemExit

    @split
    def do_sum(self, a, b):
        print (int(a) + int(b))

    @split
    def do_subtract(self, a, b):
        print (int(a) - int(b))

    @split
    def do_multiply(self, a, b):
        print (int(a) * int(b))

    @split
    def do_divide(self, a, b):
        print (int(a) / int(b))

    def do_scientific(self, args):
        sub_cmd = ScientificCalcREPL()
        sub_cmd.cmdloop()

    def do_EOF(self, args):
        raise SystemExit

if __name__ == "__main__":

    signal.signal(signal.SIGINT, singal_handler)

    CalcREPL.intro = "Welcome to the interactive REPL calculator!"

    CalcREPL().cmdloop()

    signal.pause()