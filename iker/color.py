# -*- coding: utf-8 -*-

bold = '\033[1m'
white = '\033[3m'
red = '\033[31m'
green = '\033[32m'
yellow = '\033[33m'
blue = '\033[34m'
reset = '\033[0m'

def error(msg):
    print("[%sERROR%s] %s" % (red, reset, msg))

def warning(msg):
    print("[%sWARNING%s] %s" % (yellow, reset, msg))

def info(msg):
    print("[%sINFO%s] %s" % (green, reset, msg))

def debug(msg):
    print("[%sDEBUG%s] %s" % (blue, reset, msg))
