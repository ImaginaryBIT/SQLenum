# SQL Linked Server Enumeration 

Usage: 

SQLenum.exe [target1] [target2] [options]
- Local enumeration: SQLenum.exe local
- Enumeration: SQLenum.exe SQL11
- Linked server enumeration: SQLenum.exe SQL11 SQL33

Options:

- --localImpersonation=[username] : Local impersonation, default value is sa
- --remoteImpersonation=[username] : Remote impersonation, default value is sa
- --localExecute=[commands] : OS command execution on local server;
- --remoteExecute=[commands] : OS command execution on remote server;
- --debug : Enable debug mode