#!/usr/bin/env python
# -*- coding:utf8 -*-

class ClassTest:

	def __init__(self, msg):
		self.MSG = msg

	def __enter__(self):
		print "First output"
		return self

	def __exit__(self, type, value, traceback):
		print "Fourth output"
		return isinstance(value, TypeError)

	def just_a_method(self, name):
		return "Third %s" % name


if __name__ == "__main__":

	with ClassTest("Second output") as test:
		print test.MSG
		print test.just_a_method('ouput')

	print "Fifth output"