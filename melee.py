#!/usr/bin/python

'''
Original BSD License (BSD with advertising)

Copyright (c) 2023, {Aditya K Sood - https://adityaksood.com}
All rights reserved.

Redistribution and use in source and binary forms, with or without modification,
are permitted provided that the following conditions are met:
    * Redistributions of source code must retain the above copyright notice,
    this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright notice,
    this list of conditions and the following disclaimer in the documentation
    and/or other materials provided with the distribution.
    * Neither the name of SecNiche Security Labs nor the names of its contributors
    may be used to endorse or promote products derived from this software
    without specific prior written permission.
    
THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
OF THE POSSIBILITY OF SUCH DAMAGE.
'''



import traceback
import mysql.connector as mysql_client
from mysql.connector import errorcode

lib_requirements = ['os','re','mysql.connector','time','sys','json']
for import_library in lib_requirements:
    try:
        globals()[import_library] = __import__(import_library)
    except:
        print("[-] %s - import library failed !" %(import_library))
        print("[-] tool cannot continue, please install the required librarier !")
        print("[+] pip/pip3 install %s" %(import_library))
        sys.exit(0)


def tool_banner():
    print("\t--------------------------------------------------------------------")
    t_banner = """

            __  ___________    ____________
           /  |/  / ____/ /   / ____/ ____/
          / /|_/ / __/ / /   / __/ / __/   
         / /  / / /___/ /___/ /___/ /___   
        /_/  /_/_____/_____/_____/_____/   
                                   

        MELEE (may-lay) : A Tool to Detect Potential Infections in MySQL Deployments!
        Authored by: Aditya K Sood {https://adityaksood.com} 
        """
    print(t_banner)
    print("\t--------------------------------------------------------------------")


def tool_mapper():
    print("\n[*] { MELEE } - MySQLDB Ransomware Infection Detector .....\n")
    print("[*] usage:", sys.argv[0], " <mysql host (local or remote)> <mysql service port> <mysql username> <mysql password> <module>")
    print("[*] MELEE supported modules:")
    print("     - map_mysql_geoip: map the GeoIP presence of the MySQL host")
    print("     - check_anonymous_access: verify if the remote MySQL host has anonymous access")
    print("     - enum_mysql_db_names: enumerate all the available MySQL databases")
    print("     - enum_mysql_db_tables: enumerate all the tables in active databases")
    print("     - enum_mysql_db_users: enumerate all the user names related to MySQL database (mysql.user) only")
    print("     - enum_active_users: enumerate all the logged-in users (information_schema.processlist) only")
    print("     - check_ransomware_infection: detect a potential ransomware infection")
    print("     - deep_scan_ransomware_infection: launch a deep scan to extract infected resources and a ransom message")
    print("\n[*] example:", sys.argv[0], "99.34.123.xxx 3306 root root check_ransomware_infection")
    print("[*] example:", sys.argv[0], "89.34.451.xxx 3306 root \"\" deep_scan_ransomware_infection")
    print("\n")
    print("[*] tool considerations:")
    print("     - for ransom message analysis, file is dumped to local directory with <mysql_host>_ransom_message.txt") 
    print("     - for anonymous access module, do not supply any password with username")
    print("     - for weak authentication credentials, use combinations such as <root:root>, or other combinations")

def main():
    try:
        tool_banner()
        db_hostname = str(sys.argv[1])
        db_port = sys.argv[2]
        db_username = str(sys.argv[3])
        db_password = str(sys.argv[4])

        module = str(sys.argv[5])

        module_list = ['map_mysql_geoip','check_anonymous_access','check_ransomware_infection', 'deep_scan_ransomware_infection','enum_active_users','enum_mysql_db_users','enum_mysql_db_names','enum_mysql_db_tables']
        if module not in module_list:
            print("\n[-] [MELEE> module does not exist, check for the right module and trigger execution !")
            print("[-] [MELEE> supported modules:", module_list)
            print("\n[-] Exiting the execution engine....select the supported module and run the tool again...")
            sys.exit(0)

        # get_geoip_details(db_hostname)

        if module == "check_anonymous_access":
            print("[*] executing module: check_anonymous_access .....\n")
            get_geoip_details(db_hostname)
            check_anonymous_access(db_hostname,db_port,db_username,db_password)
            sys.exit(0)

        if module == "check_ransomware_infection":
            print("[*] executing module: check_ransomware_infection .....\n")
            get_geoip_details(db_hostname)
            check_ransomware_infection(db_hostname,db_port,db_username, db_password)
            sys.exit(0)


        if module == "deep_scan_ransomware_infection":
                        print("[*] executing module: deep_scan_ransomware_infection .....\n")
                        get_geoip_details(db_hostname)
                        deep_scan_ransomware_infection(db_hostname,db_port,db_username, db_password)
                        sys.exit(0)


        if module == "enum_mysql_db_names":
            print("[*] executing module: enum_mysql_db_names .....\n")
            get_geoip_details(db_hostname)
            enum_mysql_db_names(db_hostname,db_port,db_username, db_password)
            sys.exit(0)

        if module == "enum_mysql_db_users":
                        print("[*] executing module: enum_mysql_db_users .....\n")
                        get_geoip_details(db_hostname)
                        enum_mysql_db_users(db_hostname,db_port,db_username, db_password)
                        sys.exit(0)

        if module == "enum_active_users":
            print("[*] executing module: enum_active_users .....\n")
            get_geoip_details(db_hostname)
            enum_active_users(db_hostname,db_port,db_username, db_password)
            sys.exit(0)

        if module == "enum_mysql_db_tables":
            print("[*] executing module: enum_mysql_db_tables .....\n")
            get_geoip_details(db_hostname)
            enum_mysql_db_tables(db_hostname,db_port,db_username, db_password)
            sys.exit(0)

        if module == "map_mysql_geoip":
            print("[*] executing module: map_mysql_geoip .....\n")
            get_geoip_details(db_hostname)
            sys.exit(0)



    except IndexError:
        print("\n[*] { MELEE } Tool Usage:")
        tool_mapper()
        sys.exit(0)

    except UnboundLocalError as error:
        print("[-] MySQL connection error: connection handler fails - unbound local error")
        sys.exit(0)

    except (TypeError, ValueError) as err:
        print(traceback.format_exc())
        print("[-] Error identified as either incorrect type specification or value.\n")
        print("[-] %s\n" %err)
        print("[-] Stopping the execution ..... exiting.")
        sys.exit(0) 

    except KeyboardInterrupt:
        sys.exit(0)

def get_geoip_details(ip_address):
    from geoip import geolite2
    ip_match = geolite2.lookup(ip_address)
    if ip_match is not None:
        print("[*] MySQL DB instance is located in:",ip_match.country)
        print("[*] MySQL DB instance is using timezone:",ip_match.timezone)
        print("[*] MySQL DB geolocation paramters:", ip_match.location, "\n")
    else:
        print("[-] could not fetch the geolocation details of the ip_address:", ip_address)
        pass 

def check_anonymous_access(hostname,port_num,username,password):
    try:
        print("[*] Initiating < ANONYMOUS >  access to the remote MySQL database ....")
        cnx = mysql_client.connect(user=username, password=password, host=hostname, port=port_num)
        if cnx.is_connected():
            print("[*] MySQL allows ANONYMOUS access..\n")
            print("[*] Connection identifier:", cnx.connection_id)
            print("[*] Connected to remote MySQL database hosted at:", cnx.server_host)
            print("[*] SQL mode:", cnx.sql_mode)
            print("[*] MySQL database server time zone:", cnx.time_zone)
            print("[*] MySQL database server version:", cnx.get_server_version())
        else:
            print("[*] Looks like connection has not been eastablished securely")
            print("[*] provide different combination of user/password or remote host is not reachnable")
            sys.exit(0)


    except mysql_client.Error as err:
        if err.errno == errorcode.ER_ACCESS_DENIED_ERROR:
            print("[-] error: access denied, check  user name or password") 
            sys.exit(0)
        elif err.errno == errorcode.ER_BAD_DB_ERROR:
            print("[-] Database does not exist")
            sys.exit(0)
        else:
            print("[-] Error encountered:", err)
            sys.exit(0)
    finally:
        if cnx.is_connected():
            cnx.close()
            print("\n[-] MySQL connection terminated successfully.\n")


# Module: checking ransomware infections

def check_ransomware_infection(hostname,port_num,username,password):
    try:
        print("[*] Initiating access to the remote MySQL database ....")
        cnx = mysql_client.connect(user=username, password=password, host=hostname, port=port_num, auth_plugin='mysql_native_password')
        if cnx.is_connected():
            print("[*] Activating client to initiate connection: ", cnx)
            print("[*] Connection identifier:", cnx.connection_id, "\n")
            print("[*] Connected to remote MySQL database hosted at:", cnx.server_host)
            print("[*] SQL mode:", cnx.sql_mode)
            print("[*] MySQL database server time zone:", cnx.time_zone)
            print("[*] MySQL database server version:", cnx.get_server_version())

            db_Info = cnx.get_server_info()
            print("[*] MySQL database server info:", db_Info)
            cursor = cnx.cursor()
            cursor.execute("select database();")
            record = cursor.fetchone()
            print("[*] connected to MySQL database: ", record)
            print("[*] extracting list of active databases .....\n")
            cursor = cnx.cursor(buffered=True)
            databases = ("show databases")
            cursor.execute(databases)
            for (databases) in cursor:
                print("[+] Database detected: ", [databases[0]])
                if "PWNED" in databases[0] or "RECOVER_DATABASE" in databases[0] or "README_TO_RECOVER" in databases[0] or "READ_ME" in databases[0] or "please_read_me" in databases[0] or "README" in databases[0] or "readme_to_recover" in databases[0] or "ransom" in databases[0] or "RANSOM" in databases[0]:
                    print("[*] ----------------------------------------------------------------------------------")
                    print("[+] RANSOMWARE infection has been detected on the target MySQL host:", databases[0])
                    print("[*] ----------------------------------------------------------------------------------")
                else:
                    print("[-] traces of ransomware infections not discovered...")
        else:
            pass

        print("\n[*] Ransomware infection detection module execution completed successfully.\n")
        if cnx.is_connected():
            cursor.close()
            cnx.close()
            print("\n[-] MySQL connection terminated successfully.\n")

    except mysql_client.Error as err:
        if err.errno == errorcode.ER_ACCESS_DENIED_ERROR:
            print("[-] Error: access denied, check  user name or password")
            sys.exit(0)

        elif err.errno == errorcode.ER_BAD_DB_ERROR:
            print("[-] Database does not exist")
            sys.exit(0)

        elif err.errno == 1043:
            print("[-] Bad handshake error identified. Protocol mismatch could be the reason !")
            print("[-] Reason 1: Using an old version of MySQL on your client to connect to the server with a newer MySQL version.!")
            print("[-] Reason 2: Using a new version of MySQL on your client to connect to the server with an old MySQL version !")
            print("[*] Solution: Use the same version of both client and server for successful execution!")
            print("\n")
            sys.exit(0)
        else:
            print("[-] Error encountered:", err)
            sys.exit(0)

# Module: deep scanning ransomware infections

def deep_scan_ransomware_infection(hostname,port_num,username,password):
    try:
        
        print("[*] Initiating access to the remote MySQL database ....")
        cnx = mysql_client.connect(user=username, password=password, host=hostname, port=port_num)
        if cnx.is_connected():
            print("[*] Activating client to initiate connection: ", cnx)
            print("[*] Connection identifier:", cnx.connection_id, "\n")
            print("[*] Connected to remote MySQL database hosted at:", cnx.server_host)
            print("[*] SQL mode:", cnx.sql_mode)
            print("[*] MySQL database server time zone:", cnx.time_zone)
            print("[*] MySQL database server version:", cnx.get_server_version())

            db_Info = cnx.get_server_info()
            print("[*] MySQL database server info:", db_Info)

            cursor = cnx.cursor()
            cursor.execute("select database()")
            record = cursor.fetchone()
            print("[*] connected to database: ", record)
    
            print("[*] extracting list of active databases .....\n")

            cursor = cnx.cursor(buffered=True)
            databases = ("show databases")
            cursor.execute(databases)
            for (databases) in cursor:
                print("[+] Database detected: ", [databases[0]])
                if "README_TO_RECOVER" in databases[0] or "READ_ME" in databases[0] or "please_read_me" in databases[0] or "README" in databases[0] or "readme_to_recover" in databases[0] or "ransom" in databases[0] or "RANSOM" in databases[0]:
                    print("[*] ---------------------------------------------------------------------------------")
                    print("[+] RANSOMWARE infection has baeen detected on the target MySQL host:", databases[0])
                    print("[*] ---------------------------------------------------------------------------------")
                    db_name = databases[0]
                    cnx1 = cnx.cursor(buffered=True)
                    cnx1.execute("use " + db_name)
                    cnx1.execute("show tables")
                    result = cnx1.fetchall()

                    print("[*] Dumping tables in the database:", db_name)
                    for (table_name,) in result:
                        print("[+] Table:", table_name, "\n")
                        print("[*] Dumping potential ransom message/notification")
                        print("\n--------------------------------------------------------------------------------")
                        cnx1.execute("select * from " + table_name)
                        rows = cnx1.fetchall()
                        print("[*] Total number of rows detected in the table: ", (table_name, cnx1.rowcount), "\n")
                        if cnx1.rowcount == 0:
                            print("[-] ransomware message not found, no records obtained in the suspicious table")
                            print("[-] potential trace of infected database detected but ransom message missing")
                        else:
                            for row in rows:
                                print("[R]", row)
                                f_handle=open(hostname +"_ransom_message.txt","a")
                                f_handle.writelines(str(row))
                                f_handle.writelines("\n")
                                f_handle.close()

                            print("\n[*] ransom message is also dumped to file: ", hostname +"_ransom_message.txt")
                        print("\n--------------------------------------------------------------------------------")
                else:
                    print("[-] traces of ransomware infections not discovered...")
    
        else:
            pass

        print("\n[*] Ransomware infection detection module execution completed successfully.\n")
        if cnx.is_connected():
            cursor.close()
            cnx.close()
            print("\n[-] MySQL connection terminated successfully.\n")

    except mysql_client.Error as err:
        if err.errno == errorcode.ER_ACCESS_DENIED_ERROR:
            print("[-] Error: access denied, check  user name or password")
            sys.exit(0)

        elif err.errno == errorcode.ER_BAD_DB_ERROR:
            print("[-] Database does not exist")
            sys.exit(0)

        elif err.errno == 1043:
            print("[-] Bad handshake error identified. Protocol mismatch could be the reason !")
            print("[-] Reason 1: Using an old version of MySQL on your client to connect to the server with a newer MySQL version.!")
            print("[-] Reason 2: Using a new version of MySQL on your client to connect to the server with an old MySQL version !")
            print("[*] Solution: Use the same version of both client and server for successful execution!")
            print("\n")
            sys.exit(0)
        else:
            print("[-] Error encountered:", err)
            sys.exit(0)
            
# Module: enumerating database names

def enum_mysql_db_names(hostname,port_num,username,password):
    try:
        print("[*] Initiating access to the remote MySQL database ....")
        cnx = mysql_client.connect(user=username, password=password, host=hostname, port=port_num)
        if cnx.is_connected():
            print("[*] Connection identifier:", cnx.connection_id)
            print("[*] Connected to remote MySQL database hosted at:", cnx.server_host)
            print("[*] SQL mode:", cnx.sql_mode)
            print("[*] MySQL database server time zone:", cnx.time_zone)
            print("[*] MySQL database server version:", cnx.get_server_version())

            db_Info = cnx.get_server_info()
            print("[*] MySQL database server info:", db_Info)
            cursor = cnx.cursor()
            cursor.execute("select database()")
            record = cursor.fetchone()
            print("[*] connected to database: ", record)

            print("[*] extracting list of active databases .....\n")

            cursor = cnx.cursor(buffered=True)
            databases = ("show databases")
            cursor.execute(databases)
            for (databases) in cursor:
                print("[+] Database: ", databases[0])
        print("\n[*] Database enumeration completed successfully.\n")

    except mysql_client.Error as err:
        if err.errno == errorcode.ER_ACCESS_DENIED_ERROR:
            print("[-] error: access denied, check  user name or password")
            sys.exit(0)
        
        elif err.errno == errorcode.ER_BAD_DB_ERROR:
            print("[-] Database does not exist")
            sys.exit(0)
        else:
            print("[-] Error encountered:", err)
            sys.exit(0)
    finally:
        if cnx.is_connected():
            cursor.close()
            cnx.close()
            print("\n[-] MySQL connection terminated successfully.\n")




# Module: enumerating table names

def enum_mysql_db_tables(hostname,port_num,username,password):
    try:
        print("[*] Initiating access to the remote MySQL database ....")
        cnx = mysql_client.connect(user=username, password=password, host=hostname, port=port_num)

        if cnx.is_connected():
            print("[*] Connection identifier:", cnx.connection_id)
            print("[*] Connected to remote MySQL database hosted at:", cnx.server_host)
            print("[*] SQL mode:", cnx.sql_mode)
            print("[*] MySQL database server time zone:", cnx.time_zone)
            print("[*] MySQL database server version:", cnx.get_server_version())
            
            db_Info = cnx.get_server_info()
            print("[*] MySQL database server info:", db_Info)
            
            cursor = cnx.cursor()
            cursor.execute("select database();")
            record = cursor.fetchone()
            print("[*] connected to database: ", record)
            print("[*] extracting list of active databases .....\n")

            cursor = cnx.cursor(buffered=True)
            databases = ("show databases")
            cursor.execute(databases)
            for (databases) in cursor:
            #   print("[+] Database: ", databases[0])
                db_name = databases[0]
                cnx1 = cnx.cursor(buffered=True)
                cnx1.execute("use " + db_name)
                cnx1.execute("show tables")
                result = cnx1.fetchall()
                print("[*]---------------------------------------------------")
                print("[*] Dumping tables in the database:", db_name)
                print("[*]---------------------------------------------------")
                for (table_name,) in result:
                    print("[+] Table:", table_name)

        print("\n[*] Table enumeration completed successfully.\n")

    except mysql_client.Error as err:
        if err.errno == errorcode.ER_ACCESS_DENIED_ERROR:
            print("[-] error: access denied, check  user name or password")
            sys.exit(0)
        elif err.errno == errorcode.ER_BAD_DB_ERROR:
            print("[-] Database does not exist")
            sys.exit(0)
        else:
            print("[-] Error encountered:", err)
            sys.exit(0)
    finally:
        if cnx.is_connected():
            cursor.close()
            cnx.close()
            print("\n[-] MySQL connection terminated successfully.\n")



# Module: enumerating user names in mysql database if exists

def enum_mysql_db_users(hostname,port_num,username,password):
    try:
        print("[*] Initiating access to the remote MySQL database ....")
        cnx = mysql_client.connect(user=username, password=password, host=hostname, port=port_num)

        if cnx.is_connected():
            print("[*] Connection identifier:", cnx.connection_id)
            print("[*] Connected to remote MySQL database hosted at:", cnx.server_host)
            print("[*] SQL mode:", cnx.sql_mode)
            print("[*] MySQL database server time zone:", cnx.time_zone)
            print("[*] MySQL database server version:", cnx.get_server_version())

            db_Info = cnx.get_server_info()
            print("[*] MySQL database server info:", db_Info)
            cursor = cnx.cursor()
            cursor.execute("select database()")
            record = cursor.fetchone()
            print("[*] connected to database: ", record)
            print("[*] extracting list of users from mysql database .....\n")
            cnx1 = cnx.cursor(buffered=True)
            cnx1.execute("use mysql")

            cnx1.execute("select user from mysql.user")
            result = cnx1.fetchall()
            print("[*]---------------------------------------------------")
            print("[*] Dumping users in the mysql database if exists ....")
            print("[*]---------------------------------------------------")
            # debug check: print(result)
            for (user_name,) in result:
                print("[+] User:", user_name)

        print("\n[*] User enumeration completed successfully.\n")

    except mysql_client.Error as err:
        if err.errno == errorcode.ER_ACCESS_DENIED_ERROR:
            print("[-] error: access denied, check  user name or password")
            sys.exit(0)
        elif err.errno == errorcode.ER_BAD_DB_ERROR:
            print("[-] Database does not exist")
            sys.exit(0)
        else:
            print("[-] Error encountered:", err)
            sys.exit(0)
    finally:
        if cnx.is_connected():
            cursor.close()
            cnx.close()
            print("\n[-] MySQL connection terminated successfully.\n")



# Module: enumerating active (logged-in)  users information_schema.processlist

def enum_active_users(hostname,port_num,username,password):
    try:
        print("[*] Initiating access to the remote MySQL database ....")
        cnx = mysql_client.connect(user=username, password=password, host=hostname, port=port_num)
        if cnx.is_connected():
            print("[*] Connection identifier:", cnx.connection_id)
            print("[*] Connected to remote MySQL database hosted at:", cnx.server_host)
            print("[*] SQL mode:", cnx.sql_mode)
            print("[*] MySQL database server time zone:", cnx.time_zone)
            print("[*] MySQL database server version:", cnx.get_server_version())

            db_Info = cnx.get_server_info()
            print("[*] MySQL database server info:", db_Info)
            cursor = cnx.cursor()
            cursor.execute("select database()")
            record = cursor.fetchone()
            print("[*] connected to database: ", record)
            print("[*] extracting list of logged-in users and hosts from information_schema database .....\n")
            cnx1 = cnx.cursor(buffered=True)
            cnx1.execute("use information_schema")
        
            cnx1.execute("select user,host from information_schema.processlist")
            result = cnx1.fetchall()
            print("[*]--------------------------------------------------------------------------")
            print("[*] Dumping logged-in users in the information_schema database if exists ....")
            print("[*]--------------------------------------------------------------------------")

            for (user_name,host) in result:
                print("[+] User:Host", user_name, host)

        print("\n[*] User enumeration completed successfully.\n")

    except mysql_client.Error as err:
        if err.errno == errorcode.ER_ACCESS_DENIED_ERROR:
            print("[-] error: access denied, check  user name or password")
            sys.exit(0)

        elif err.errno == errorcode.ER_BAD_DB_ERROR:
            print("[-] Database does not exist")
            sys.exit(0)

        else:
            print("[-] Error encountered:", err)
            sys.exit(0)

    finally:
        if cnx.is_connected():
            cursor.close()
            cnx.close()
            print("\n[-] MySQL connection terminated successfully.\n")

if __name__=="__main__":
    main()
