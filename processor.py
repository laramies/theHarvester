import sys

filename = "vascolist.txt"
files = open(filename, 'r')
list = files.readlines()

for x in list:
    x = x.strip()
    a = x.split(" ")
    if len(a) == 2:
        print a[0] + "." + a[1] + "@vasco.com"
