#!/usr/bin/env python
# -*- coding:utf8 -*-


import inspect
import shlex
import signal
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


class CalcREPL(Cmd):

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

    def do_EOF(self, args):
        raise SystemExit

if __name__ == "__main__":

    print dir(signal)
    signal.signal(signal.SIGINT, singal_handler)

    CalcREPL.prompt = "[>>] "

    CalcREPL.intro = "Welcome to the interactive REPL calculator!"

    CalcREPL().cmdloop()

    signal.pause()