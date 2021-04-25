# A C sharp tool for SQL Enumeration 

Usage: 

SQLcheck.exe [target1] [target2] [options]

Local enumeration: SQLcheck.exe local
Enumeration: SQLcheck.exe SQL11
Linked server enumeration: SQLcheck.exe SQL11 SQL33

Options:
--localImpersonation=[username] : Local impersonation, default value is sa
--remoteImpersonation=[username] : Remote impersonation, default value is sa
--execute=[commands] : Remote command execution
--debug : Enable debug mode