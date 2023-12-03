#! /usr/bin/python3
"""-*- encoding: utf-8 -*-

woof (Web Offer One File) -- an ad-hoc single file webserver
Copyright (C) 2004-2009 Simon Budig  <simon@budig.de>
http://www.home.unix-ag.org/simon/woof.html

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

A copy of the GNU General Public License is available at
http://www.fsf.org/licenses/gpl.txt, you can also write to the
Free Software  Foundation, Inc., 59 Temple Place - Suite 330,
Boston, MA 02111-1307, USA.

Darwin support with the help from Mat Caughron
    <mat@phpconsulting.com>
Solaris support by Colin Marquardt <colin.marquardt@zmd.de>
FreeBSD support with the help from Andy Gimblett
    <A.M.Gimblett@swansea.ac.uk>
Cygwin support by Stefan Reichör <stefan@xsteve.at>
tarfile usage suggested by Morgan Lefieux <comete@geekandfree.org>
File upload support loosely based on code from Stephen English
    <steve@secomputing.co.uk>
Python 3 port by Timothy Eng <3166604+timotree@users.noreply.github.com>
"""
import cgi
import configparser
import errno
import getopt
from http.server import BaseHTTPRequestHandler, HTTPServer
import os
import shutil
import socket
from socketserver import ThreadingMixIn
import struct
import sys
import tarfile
import tempfile
import urllib
import zipfile

COMPRESS_METHOD = 'gz'
HTTPD = None
IS_UPLOAD_MODE = False
MAX_DOWNLOADS = 1


class EvilZipStreamWrapper():
    """Wrapper for the Evil Zip Stream."""
    def __init__(self, victim):
        self.victim_fd = victim
        self.position = 0
        self.tells = []
        self.in_file_data = 0

    def __getattr__(self, name):
        return getattr(self.victim_fd, name)

    def tell(self):
        """Return the current stream position."""
        self.tells.append(self.position)

        return self.position

    def seek(self, offset, whence=0):
        """Change the stream position to the given byte offset. The
        default value for whence is SEEK_SET.

        :param offset: Offset amount relative to the position indicated
            by whence
        :param whence: (Optional) Starting position for seek.
            Values:
                SEEK_SET or 0 – start of the stream (the default);
                    offset should be zero or positive
                SEEK_CUR or 1 – current stream position; offset may be
                    negative
                SEEK_END or 2 – end of the stream; offset is usually
                    negative
        :return: New absolute position
        """
        if offset == 0:
            return

        if offset == self.tells[0] + 14:
            # The zipfile module tries to fix up the file header.
            # Write Data descriptor header instead, the next write from
            # zipfile is CRC, compressed_size and file_size (as
            # required)
            self.write('PK\007\010')
        elif offset == self.tells[1]:
            # The zipfile module goes to the end of the file. The next
            # data written definitely is infrastructure
            # (in_file_data = 0)
            self.tells = []
            self.in_file_data = 0
        else:
            raise 'Unexpected seek for EvilZipStreamWrapper'

    def write(self, data):
        """Write the given bytes-like object to the underlying raw
        stream.

        :param data: Bytes-like object to write
        :return: Number of bytes written
        """
        # Only test for headers if we know that we're not writing
        # (potentially compressed) data.
        if self.in_file_data == 0:
            if data[:4] == zipfile.stringFileHeader:
                # fix the file header for extra Data descriptor
                hdr = list(struct.unpack(zipfile.structFileHeader, data[:30]))
                hdr[3] |= (1 << 3)
                data = struct.pack(zipfile.structFileHeader, *hdr) + data[30:]
                self.in_file_data = 1
            elif data[:4] == zipfile.stringCentralDir:
                # fix the directory entry to match file header.
                hdr = list(struct.unpack(zipfile.structCentralDir, data[:46]))
                hdr[5] |= (1 << 3)
                data = struct.pack(zipfile.structCentralDir, *hdr) + data[46:]

        self.position += len(data)
        self.victim_fd.write(data)


class FileServHTTPRequestHandler(BaseHTTPRequestHandler):
    """Main class implementing an HTTPRequestHandler. It serves just a
    single file and redirects all other requests to this file (this
    passes the actual filename to the client).

    Currently it is impossible to serve different files with different
    instances of this class.
    """
    server_version = 'Simons FileServer'
    protocol_version = 'HTTP/1.0'
    path = None
    filename = '-'

    def log_request(self, code='-', size='-'):
        """Logs an accepted (successful) request.

        :param code: (Optional) Should specify the numeric HTTP code
            associated with the response
        :param size: (optional) Size of the response
        """
        if code == 200:
            BaseHTTPRequestHandler.log_request(self, code, size)

    def do_POST(self):
        """Handles file uploads by serving the 'POST' request type."""
        global HTTPD
        global IS_UPLOAD_MODE
        global MAX_DOWNLOADS

        # Error 501, “Can only POST to CGI scripts”, is thrown when
        # trying to POST to a non-CGI url
        if not IS_UPLOAD_MODE:
            self.send_error(501, 'Unsupported method (POST)')
            return

        MAX_DOWNLOADS -= 1

        # Shut down after we've reach the max download limit
        if MAX_DOWNLOADS < 1:
            HTTPD.shutdown()

        # Taken from: (dead link)
        # http://mail.python.org/pipermail/python-list/2006-September/402441.html

        form = cgi.FieldStorage(
            fp=self.rfile,
            headers=self.headers,
            environ={'REQUEST_METHOD': 'POST'},
            keep_blank_values=1,
            strict_parsing=1
        )
        if 'upfile' not in form:
            self.send_error(403, 'No upload provided')
            return
        # if not (upfile := form.getvalue('upfile')):
        #     self.send_error(403, 'No upload provided')
        #     return

        upfile = form['upfile']
        if not upfile.file or not upfile.filename:
            self.send_error(403, 'No upload provided')
            return

        upfile_name = upfile.filename
        if '\\' in upfile_name:
            upfile_name = upfile_name.split('\\')[-1]

        upfile_name = os.path.basename(upfile.filename)

        # TODO: Find a nicer way to do this
        # Increment extensions until a free one is found
        dest_file = None
        for suffix in [
            '', '.1', '.2', '.3', '.4', '.5', '.6', '.7', '.8', '.9'
        ]:
            dest_file_name = os.path.join('.', f'{upfile_name}{suffix}')
            if not os.path.exists(dest_file_name):
                break

        # Leading "0o" casts to an octal integer
        dest_file = os.open(
            dest_file_name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644
        )

        if not dest_file:
            upfile_name += '.'
            dest_file, dest_file_name = tempfile.mkstemp(
                prefix=upfile_name, dir='.'
            )

        print(
            f'Accepting uploaded file: {upfile_name} -> {dest_file_name}',
            file=sys.stderr
        )

        # TODO: Fix file permissions after outputting
        # TODO: Do os.open and os.fdopen need to be closed?
        shutil.copyfileobj(upfile.file, os.fdopen(dest_file, 'wb'))

        if upfile.done == -1:
            self.send_error(408, 'Upload interrupted')

        txt = b"""
            <html>
                <head>
                    <title>Woof Upload</title>
                </head>
                <body>
                    <h1>Woof Upload complete</h1>
                    <p>Thanks a lot!</p>
                </body>
            </html>"""
        self.send_response(200)
        self.send_header('Content-Type', 'text/html')
        self.send_header('Content-Length', str(len(txt)))
        self.end_headers()
        self.wfile.write(txt)

    def do_GET(self):
        """The request is mapped to a local file by interpreting the
        request as a path relative to the current working directory.
        """
        global COMPRESS_METHOD
        global HTTPD
        global IS_UPLOAD_MODE
        global MAX_DOWNLOADS

        # Form for uploading a file
        if IS_UPLOAD_MODE:
            txt = b"""
                <html>
                    <head>
                        <title>Woof Upload</title>
                    </head>
                    <body>
                        <h1>Woof Upload</h1>
                        <form name="upload" method="POST" enctype="multipart/form-data">
                            <p><input type="file" name="upfile" /></p>
                            <p><input type="submit" value="Upload!" /></p>
                        </form>
                    </body>
                </html>"""
            self.send_response(200)
            self.send_header('Content-Type', 'text/html')
            self.send_header('Content-Length', str(len(txt)))
            self.end_headers()
            self.wfile.write(txt)
            return

        # Redirect any request to the filename of the file to serve.
        # This hands over the filename to the client.

        self.path = urllib.parse.quote(urllib.parse.unquote(self.path))
        location = f'/{urllib.parse.quote(os.path.basename(self.filename))}'
        if os.path.isdir(self.filename):
            if COMPRESS_METHOD == 'gz':
                location += '.tar.gz'
            elif COMPRESS_METHOD == 'bz2':
                location += '.tar.bz2'
            elif COMPRESS_METHOD == 'zip':
                location += '.zip'
            else:
                location += '.tar'

        if self.path != location:
            txt = f"""
                <html>
                    <head>
                        <title>302 Found</title>
                    </head>
                    <body>
                        302 Found <a href="{location}">here</a>.
                    </body>
                </html>""".encode()
            self.send_response(302)
            self.send_header('Location', location)
            self.send_header('Content-Type', 'text/html')
            self.send_header('Content-Length', str(len(txt)))
            self.end_headers()
            self.wfile.write(txt)
            return

        MAX_DOWNLOADS -= 1

        # Shut down after we've reach the max download limit
        if MAX_DOWNLOADS < 1:
            HTTPD.shutdown()

        file_type = None

        if os.path.isfile(self.filename):
            file_type = 'file'
        elif os.path.isdir(self.filename):
            file_type = 'dir'
        elif self.filename == '-':
            file_type = 'stdin'

        if not file_type:
            print(
                'Can only serve files, directories, or stdin. Aborting.',
                file=sys.stderr
            )
            sys.exit(1)

        self.send_response(200)
        self.send_header('Content-Type', 'application/octet-stream')
        if os.path.isfile(self.filename):
            self.send_header('Content-Length', os.path.getsize(self.filename))
        self.end_headers()

        try:
            if file_type == 'file':
                with open(self.filename, 'rb') as datafile:
                    shutil.copyfileobj(datafile, self.wfile)
            elif file_type == 'dir':
                self._compress_dir()
            elif file_type == 'stdin':
                datafile = sys.stdin
                shutil.copyfileobj(datafile, self.wfile)
        except Exception as e:
            print(e)
            print('Connection broke. Aborting', file=sys.stderr)

    def _compress_dir(self):
        # Tarballs
        if COMPRESS_METHOD != 'zip':
            with tarfile.open(
                mode=(f'w|{COMPRESS_METHOD}'), fileobj=self.wfile
            ) as tfile:
                tfile.add(
                    self.filename, arcname=os.path.basename(self.filename)
                )
            return

        # Zip files
        ezfile = EvilZipStreamWrapper(self.wfile)
        with zipfile.ZipFile(ezfile, 'w', zipfile.ZIP_DEFLATED) as zfile:
            stripoff = os.path.dirname(self.filename) + os.sep

            for root, _, files in os.walk(self.filename):
                for file_name in files:
                    filename = os.path.join(root, file_name)
                    if filename[:len(stripoff)] != stripoff:
                        raise RuntimeError(
                            'Invalid filename assumptions, please report!'
                        )
                    zfile.write(filename, filename[len(stripoff):])


class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    """Handle requests in a separate thread"""


def find_ip():
    """Utility function to guess the IP (as a string) where the server
    can be reached from the outside. Quite nasty problem actually.
    """
    # We get a UDP socket for the test networks reserved by IANA. It is
    # highly unlikely that there is special routing used for these
    # networks, hence the socket should give us the IP address of the
    # default route. We're doing multiple tests, to guard against the
    # computer being part of a test installation.

    candidates = []
    for test_ip in ['192.0.2.0', '198.51.100.0', '203.0.113.0']:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as my_socket:
            my_socket.connect((test_ip, 80))
            ip_addr = my_socket.getsockname()[0]

        if ip_addr in candidates:
            return ip_addr

        candidates.append(ip_addr)

    return candidates[0]


def serve_files(filename, max_downloads=1, ip_addr='', port=8080):
    global HTTPD
    global MAX_DOWNLOADS

    MAX_DOWNLOADS = max_downloads

    # We have to somehow push the filename of the file to serve to the
    # class handling the requests. This is an evil way to do this...
    FileServHTTPRequestHandler.filename = filename

    try:
        HTTPD = ThreadedHTTPServer((ip_addr, port), FileServHTTPRequestHandler)
    except socket.error:
        print(
            f"Cannot bind to IP address '{ip_addr}' port {port}",
            file=sys.stderr
        )
        sys.exit(1)

    if not ip_addr:
        ip_addr = find_ip()

    if ip_addr:
        print(f'Now serving on http://{ip_addr}:{port}/')
        HTTPD.serve_forever()


def usage(port, max_downloads, errmsg=None):
    name = os.path.basename(sys.argv[0])
    print(
        f"""Usage: {name} [-i <ip_addr>] [-p <port>] [-c <count>] [<file>]
              {name} [-i <ip_addr>] [-p <port>] [-c <count>] [-z|-j|-Z|-u] <dir>
              {name} [-i <ip_addr>] [-p <port>] [-c <count>] -s
              {name} [-i <ip_addr>] [-p <port>] [-c <count>] -U
    
     Serves a single file <count> times via http on port <port> on IP
     address <ip_addr>.

     When no filename is specified, or set to '-', then stdin will be read.

     When a directory is specified, an tar archive gets served. By default
     it is gzip compressed. You can specify -z for gzip compression, -j for
     bzip2 compression, -Z for ZIP compression or -u for no compression.
     You can configure your default compression method in the configuration
     file described below.

     When -s is specified instead of a filename, {name} distributes itself.

     When -U is specified, woof provides an upload form and allows uploading
     files.
    
     defaults: count = {max_downloads}, port = {port}

     You can specify different defaults in two locations: /etc/woofrc
     and ~/.woofrc can be INI-style config files containing the default
     port and the default count. The file in the home directory takes
     precedence. The compression methods are "off", "gz", "bz2" or "zip".

     Sample file:

          [main]
          port = 8008
          count = 2
          ip = 127.0.0.1
          compressed = gz
    """,
        file=sys.stderr
    )

    if errmsg:
        print(f'{errmsg}\n\n', file=sys.stderr)

    sys.exit(1)


def main():
    """Main entry point."""
    global COMPRESS_METHOD
    global IS_UPLOAD_MODE

    filename = None

    # Read config options if a file is present
    config = configparser.ConfigParser()
    config.read(['/etc/woofrc', os.path.expanduser('~/.woofrc')])

    port = config.getint('main', 'port', fallback=8080)
    max_downloads = config.getint('main', 'count', fallback=1)
    ip_addr = config.get('main', 'ip', fallback='')

    formats = {
        'gz': 'gz',
        'bz': 'bz2',  # Coerced to bz2
        'bz2': 'bz2',
        'zip': 'zip',
        'true': 'gz',  # Coerced to gz
        'false': '',
        'off': ''
    }
    compressed = config.get('main', 'compressed', fallback='gz')
    COMPRESS_METHOD = formats.get(compressed, 'gz')

    default_port = port
    default_max_downloads = max_downloads

    try:
        options, filenames = getopt.getopt(sys.argv[1:], 'hUszjZui:c:p:')
    except getopt.GetoptError as desc:
        usage(default_port, default_max_downloads, desc)

    for option, val in options:
        # Download count
        if option == '-c':
            try:
                if (max_downloads := int(val)) <= 0:
                    raise ValueError
            except ValueError:
                usage(
                    default_port, default_max_downloads, (
                        f'Invalid download count: {val}. Please specify an '
                        'integer >= 0.'
                    )
                )
        # IP address
        elif option == '-i':
            ip_addr = val
        # Port
        elif option == '-p':
            try:
                if not (0 <= (port := int(val)) <= 65535):
                    raise ValueError
            except ValueError:
                usage(
                    default_port, default_max_downloads, (
                        f'Invalid port number: {val}. Please specify an integer'
                        'between 0 and 65535.'
                    )
                )
        # Self-distribution
        elif option == '-s':
            filenames.append(__file__)
        # Help
        elif option == '-h':
            usage(default_port, default_max_downloads)
        # Upload mode
        elif option == '-U':
            IS_UPLOAD_MODE = True
        # Enable gzip compression
        elif option == '-z':
            COMPRESS_METHOD = 'gz'
        # Enable bzip2 compression
        elif option == '-j':
            COMPRESS_METHOD = 'bz2'
        # Enable zip compression
        elif option == '-Z':
            COMPRESS_METHOD = 'zip'
        # No compression
        elif option == '-u':
            COMPRESS_METHOD = ''
        # Unknown option
        else:
            usage(
                default_port, default_max_downloads, f'Unknown option: {option}'
            )

    # Upload mode can't be enabled if a filename is supplied
    if IS_UPLOAD_MODE and filenames:
        usage(
            default_port, default_max_downloads,
            'Conflicting usage: simultaneous up- and download not supported'
        )

    if len(filenames) == 1:
        filename = '-'

        if filenames[0] != '-':
            filename = os.path.abspath(filenames[0])

            # Check if file exists
            if not os.path.exists(filename):
                usage(
                    default_port, default_max_downloads,
                    'Can only serve single files/directories'
                )

            if not (os.path.isfile(filename) or os.path.isdir(filename)):
                usage(
                    default_port, default_max_downloads,
                    f'{filenames[0]}: Neither file nor directory'
                )

    serve_files(filename, max_downloads, ip_addr, port)


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        pass
