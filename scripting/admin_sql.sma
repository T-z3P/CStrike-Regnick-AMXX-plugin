/* AMX Mod X script.
*   Admin Base Plugin
*
* by the AMX Mod X Development Team
*  originally developed by OLO
*
* This file is part of AMX Mod X.
*
*
*  This program is free software; you can redistribute it and/or modify it
*  under the terms of the GNU General Public License as published by the
*  Free Software Foundation; either version 2 of the License, or (at
*  your option) any later version.
*
*  This program is distributed in the hope that it will be useful, but
*  WITHOUT ANY WARRANTY; without even the implied warranty of
*  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
*  General Public License for more details.
*
*  You should have received a copy of the GNU General Public License
*  along with this program; if not, write to the Free Software Foundation,
*  Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
*
*  In addition, as a special exception, the author gives permission to
*  link the code of this program with the Half-Life Game Engine ("HL
*  Engine") and Modified Game Libraries ("MODs") developed by Valve,
*  L.L.C ("Valve"). You must obey the GNU General Public License in all
*  respects for all of the code used other than the HL Engine and MODs
*  from Valve. If you modify this file, you may extend this exception
*  to your version of the file, but you are not obligated to do so. If
*  you do not wish to do so, delete this exception statement from your
*  version.
*/

// Uncomment for SQL version
#define USING_SQL

// Uncomment for CStrike-Regnick debug
#define RN_DEBUG

/**
 * Uncomment for passwords encryption
 * 	- not used for now
 */
//#define RN_ENC_PASSWD

#include <amxmodx>
#include <amxmisc>
#if defined USING_SQL
#include <sqlx>
#include <regnick>
#endif

//new Vector:AdminList;

new AdminCount;

#define ADMIN_LOOKUP	(1<<0)
#define ADMIN_NORMAL	(1<<1)
#define ADMIN_STEAM		(1<<2)
#define ADMIN_IPADDR	(1<<3)
#define ADMIN_NAME		(1<<4)

new g_cmdLoopback[16]
new bool:g_CaseSensitiveName[33];

// pcvars
new amx_mode;
new amx_password_field;
new amx_default_access;

// CStrike-Regnick
new Handle:g_Tuple;

enum _:RegData
{
    REG_ID,
    REG_USER[33],
	REG_USER_SAFE[128],
	REG_PASS[65],
	REG_PASS_SAFE[65],
    REG_EMAIL[65],
	REG_EMAIL_SAFE[128],
	REG_KEY[33]
};
new g_eRegData[RegData];


public plugin_init()
{
#if defined USING_SQL
	register_plugin("Admin Base (SQL)", AMXX_VERSION_STR, "AMXX Dev Team & Gentle Software Solutions")
#else
	register_plugin("Admin Base", AMXX_VERSION_STR, "AMXX Dev Team")
#endif
	register_dictionary("admin.txt")
	register_dictionary("common.txt")
	amx_mode			= register_cvar("amx_mode", "1")
	amx_password_field	= register_cvar("amx_password_field", "_pw")
	amx_default_access	= register_cvar("amx_default_access", "")
	
	register_cvar("amx_vote_ratio", "0.02")
	register_cvar("amx_vote_time", "10")
	register_cvar("amx_vote_answers", "1")
	register_cvar("amx_vote_delay", "60")
	register_cvar("amx_last_voting", "0")
	register_cvar("amx_show_activity", "2")
	register_cvar("amx_votekick_ratio", "0.40")
	register_cvar("amx_voteban_ratio", "0.40")
	register_cvar("amx_votemap_ratio", "0.40")

	set_cvar_float("amx_last_voting", 0.0)

#if defined USING_SQL
	register_srvcmd("amx_sqladmins", "adminSql")
	
	register_cvar("amx_sql_table_prefix", "")
	register_cvar("amx_rn_serverid", "0");
	register_cvar("amx_rn_groupid", "0");
	register_cvar("amx_rn_user_reg", "0");
	register_cvar("amx_rn_account_type","0") 
	register_cvar("amx_rn_message","1")
	register_cvar("amx_rn_message_site","http://yoursitehere.com")
	register_cvar("amx_rn_message_time","300.0") // Float
#endif
	register_cvar("amx_sql_host", "127.0.0.1")
	register_cvar("amx_sql_user", "root")
	register_cvar("amx_sql_pass", "")
	register_cvar("amx_sql_db", "amx")
	register_cvar("amx_sql_type", "mysql")

	register_concmd("amx_reloadadmins", "cmdReload", ADMIN_CFG)
	register_concmd("register", "RNRegister", ADMIN_USER, "<e-mail> <password> - register current nickname in database")

	format(g_cmdLoopback, 15, "amxauth%c%c%c%c", random_num('A', 'Z'), random_num('A', 'Z'), random_num('A', 'Z'), random_num('A', 'Z'))

	register_clcmd(g_cmdLoopback, "ackSignal")

	remove_user_flags(0, read_flags("z"))		// Remove 'user' flag from server rights

	new configsDir[64]
	get_configsdir(configsDir, 63)
	
	server_cmd("exec %s/amxx.cfg", configsDir)	// Execute main configuration file
	server_cmd("exec %s/sql.cfg", configsDir)

	// Create a vector of 5 cells to store the info.
	//AdminList=vector_create(5);

	
#if defined USING_SQL
	server_cmd("amx_sqladmins")
#else
	format(configsDir, 63, "%s/users.ini", configsDir)
	loadSettings(configsDir)					// Load admins accounts
#endif
}
public client_connect(id)
{
	g_CaseSensitiveName[id] = false;
}

public client_disconnect(id)
{
	#if defined USING_SQL
	if((get_user_flags(id) & ADMIN_LEVEL_F)) 
	{
		new error[128], errno;
		new Handle:info = SQL_MakeStdTuple()
		new Handle:sql	= SQL_Connect(info, errno, error, 127)
		new name[32]
		new register_date = get_systime()
		
		get_user_name(id,name,31)
		
		new Handle:query = SQL_PrepareQuery(sql, "UPDATE `%s` SET `last_login`='%d' WHERE (`login` = '%s')", table_prefix("users"), register_date, name)
		
		if (!SQL_Execute(query))
		{
			SQL_QueryError(query, error, 127)
			server_print("[AMXX] SQL Error: %s", error)
			
			return PLUGIN_HANDLED
		} 
	
		SQL_FreeHandle(query)
		SQL_FreeHandle(sql)
		SQL_FreeHandle(info)
	}
	
	return PLUGIN_HANDLED
	#endif
}

public plugin_cfg()
{
	set_task(6.1, "delayed_load")
}

public delayed_load()
{
	new configFile[128], curMap[64], configDir[128]

	get_configsdir(configDir, sizeof(configDir)-1)
	get_mapname(curMap, sizeof(curMap)-1)

	new i=0;
	
	while (curMap[i] != '_' && curMap[i++] != '^0') {/*do nothing*/}
	
	if (curMap[i]=='_')
	{
		// this map has a prefix
		curMap[i]='^0';
		formatex(configFile, sizeof(configFile)-1, "%s/maps/prefix_%s.cfg", configDir, curMap);

		if (file_exists(configFile))
		{
			server_cmd("exec %s", configFile);
		}
	}

	get_mapname(curMap, sizeof(curMap)-1)

	
	formatex(configFile, sizeof(configFile)-1, "%s/maps/%s.cfg", configDir, curMap)

	if (file_exists(configFile))
	{
		server_cmd("exec %s", configFile)
	}
	
	// CStrike-Regnick
	g_Tuple = SQL_MakeStdTuple();
	
	#if defined RN_DEBUG
		new tbl_prefix[32]
		get_cvar_string("amx_sql_table_prefix", tbl_prefix, charsmax(tbl_prefix))
		
		new website[128]
		get_cvar_string("amx_rn_message_site", website, charsmax(website))
		
		server_print("[RN_DEBUG] Table prefix: %s", tbl_prefix)
		server_print("[RN_DEBUG] Using server ID: %d", get_cvar_num("amx_rn_serverid"))
		server_print("[RN_DEBUG] Using group ID: %d", get_cvar_num("amx_rn_groupid"))
		server_print("[RN_DEBUG] User registration: %d", get_cvar_num("amx_rn_user_reg"))
		server_print("[RN_DEBUG] Account type: %d", get_cvar_num("amx_rn_account_type"))
		server_print("[RN_DEBUG] Show info message to unregistred users: %d", get_cvar_num("amx_rn_message"))
		server_print("[RN_DEBUG] Info message time show: %f", get_cvar_float("amx_rn_message_time") )
		server_print("[RN_DEBUG] CStrike-Regnick website: %s", website)
	#endif
}

loadSettings(szFilename[])
{
	new File=fopen(szFilename,"r");
	
	if (File)
	{
		new Text[512];
		new Flags[32];
		new Access[32]
		new AuthData[44];
		new Password[32];
		
		while (!feof(File))
		{
			fgets(File,Text,sizeof(Text)-1);
			
			trim(Text);
			
			// comment
			if (Text[0]==';') 
			{
				continue;
			}
			
			Flags[0]=0;
			Access[0]=0;
			AuthData[0]=0;
			Password[0]=0;
			
			// not enough parameters
			if (parse(Text,AuthData,sizeof(AuthData)-1,Password,sizeof(Password)-1,Access,sizeof(Access)-1,Flags,sizeof(Flags)-1) < 2)
			{
				continue;
			}
			
			admins_push(AuthData,Password,read_flags(Access),read_flags(Flags));

			AdminCount++;
		}
		
		fclose(File);
	}

	if (AdminCount == 1)
	{
		server_print("[AMXX] %L", LANG_SERVER, "LOADED_ADMIN");
	}
	else
	{
		server_print("[AMXX] %L", LANG_SERVER, "LOADED_ADMINS", AdminCount);
	}
	
	return 1;
}

#if defined USING_SQL
public adminSql()
{
	new error[128], type[12], errno;
	
	new Handle:info = SQL_MakeStdTuple()
	new Handle:sql	= SQL_Connect(info, errno, error, 127)
	
	server_print("[AMXX] Using serverID = %d ", get_cvar_num("amx_rn_serverid"));

	SQL_GetAffinity(type, 11)
	
	if (sql == Empty_Handle)
	{
		server_print("[AMXX] %L", LANG_SERVER, "SQL_CANT_CON", error)
		
		//backup to users.ini
		new configsDir[64]
		
		get_configsdir(configsDir, 63)
		format(configsDir, 63, "%s/users.ini", configsDir)
		loadSettings(configsDir) // Load admins accounts

		return PLUGIN_HANDLED
	}

	new Handle:query
	
	if (equali(type, "sqlite"))
	{
		server_print("[AMXX] CStrike-Regnick does not support sqlite backend for the moment.");
		
	} else {
		
		query = SQL_PrepareQuery(sql, "\
			SELECT \
			    usr.login, usr.password, usr.account_flags, grp.name, grp.access \
			FROM \
			    %s usr \
			INNER JOIN (\
			    SELECT \
				user_ID, server_ID, group_ID \
			    FROM \
				%s \
			    WHERE \
				(server_ID = '0' OR server_ID = '%d') \
			    ORDER BY server_ID ASC ) as acc \
			INNER JOIN \
			    %s grp \
			ON \
			    (acc.user_ID = usr.ID) AND (acc.group_ID = grp.ID) \
			WHERE \
			    (usr.active = 1) \
			GROUP by usr.login;", 
				table_prefix("users"), 
				table_prefix("users_access"), 
				get_cvar_num("amx_rn_serverid"), 
				table_prefix("groups") 
			);
	}
	

	if (!SQL_Execute(query))
	{
		SQL_QueryError(query, error, 127)
		server_print("[AMXX] %L", LANG_SERVER, "SQL_CANT_LOAD_ADMINS", error)
	} else if (!SQL_NumResults(query)) {
		server_print("[AMXX] %L", LANG_SERVER, "NO_ADMINS")
	} else {
		
		AdminCount = 0
		
		/** do this incase people change the query order and forget to modify below */
		new qcolAuth = SQL_FieldNameToNum(query, "login")
		new qcolPass = SQL_FieldNameToNum(query, "password")
		new qcolAccess = SQL_FieldNameToNum(query, "access")
		new qcolFlags = SQL_FieldNameToNum(query, "account_flags")
		
		new AuthData[44];
		new Password[44];
		new Access[32];
		new Flags[32];
		
		while (SQL_MoreResults(query))
		{
			SQL_ReadResult(query, qcolAuth, AuthData, sizeof(AuthData)-1);
			SQL_ReadResult(query, qcolPass, Password, sizeof(Password)-1);
			SQL_ReadResult(query, qcolAccess, Access, sizeof(Access)-1);
			SQL_ReadResult(query, qcolFlags, Flags, sizeof(Flags)-1);
	
			admins_push(AuthData,Password,read_flags(Access),read_flags(Flags));
	
			++AdminCount;
			SQL_NextRow(query)
		}
	
		if (AdminCount == 1)
		{
			server_print("[AMXX] %L", LANG_SERVER, "SQL_LOADED_ADMIN")
		}
		else
		{
			server_print("[AMXX] %L", LANG_SERVER, "SQL_LOADED_ADMINS", AdminCount)
		}
		
		SQL_FreeHandle(query)
		SQL_FreeHandle(sql)
		SQL_FreeHandle(info)
	}
	
	return PLUGIN_HANDLED
}
#endif

public cmdReload(id, level, cid)
{
	if (!cmd_access(id, level, cid, 1))
		return PLUGIN_HANDLED

	//strip original flags (patch submitted by mrhunt)
	remove_user_flags(0, read_flags("z"))
	
	admins_flush();

#if !defined USING_SQL
	new filename[128]
	
	get_configsdir(filename, 127)
	format(filename, 63, "%s/users.ini", filename)

	AdminCount = 0;
	loadSettings(filename);		// Re-Load admins accounts

	if (id != 0)
	{
		if (AdminCount == 1)
		{
			console_print(id, "[AMXX] %L", LANG_SERVER, "LOADED_ADMIN");
		}
		else
		{
			console_print(id, "[AMXX] %L", LANG_SERVER, "LOADED_ADMINS", AdminCount);
		}
	}
#else
	AdminCount = 0
	adminSql()

	if (id != 0)
	{
		if (AdminCount == 1)
			console_print(id, "[AMXX] %L", LANG_SERVER, "SQL_LOADED_ADMIN")
		else
			console_print(id, "[AMXX] %L", LANG_SERVER, "SQL_LOADED_ADMINS", AdminCount)
	}
#endif

	new players[32], num, pv
	new name[32]
	get_players(players, num)
	for (new i=0; i<num; i++)
	{
		pv = players[i]
		get_user_name(pv, name, 31)
		accessUser(pv, name)
	}

	return PLUGIN_HANDLED
}

getAccess(id, name[], authid[], ip[], password[])
{
	new index = -1
	new result = 0
	
	static Count;
	static Flags;
	static Access;
	static AuthData[44];
	static Password[32];
	
	g_CaseSensitiveName[id] = false;

	Count=admins_num();
	for (new i = 0; i < Count; ++i)
	{
		Flags=admins_lookup(i,AdminProp_Flags);
		admins_lookup(i,AdminProp_Auth,AuthData,sizeof(AuthData)-1);
		
		if (Flags & FLAG_AUTHID)
		{
			if (equal(authid, AuthData))
			{
				index = i
				break
			}
		}
		else if (Flags & FLAG_IP)
		{
			new c = strlen(AuthData)
			
			if (AuthData[c - 1] == '.')		/* check if this is not a xxx.xxx. format */
			{
				if (equal(AuthData, ip, c))
				{
					index = i
					break
				}
			}									/* in other case an IP must just match */
			else if (equal(ip, AuthData))
			{
				index = i
				break
			}
		} 
		else 
		{
			if (Flags & FLAG_CASE_SENSITIVE)
			{
				if (Flags & FLAG_TAG)
				{
					if (contain(name, AuthData) != -1)
					{
						index = i
						g_CaseSensitiveName[id] = true
						break
					}
				}
				else if (equal(name, AuthData))
				{
					index = i
					g_CaseSensitiveName[id] = true
					break
				}
			}
			else
			{
				if (Flags & FLAG_TAG)
				{
					if (containi(name, AuthData) != -1)
					{
						index = i
						break
					}
				}
				else if (equali(name, AuthData))
				{
					index = i
					break
				}
			}
		}
	}

	if (index != -1)
	{
		Access=admins_lookup(index,AdminProp_Access);

		if (Flags & FLAG_NOPASS)
		{
			result |= 8
			new sflags[32]
			
			get_flags(Access, sflags, 31)
			set_user_flags(id, Access)
			
			log_amx("Login: ^"%s<%d><%s><>^" became an admin (account ^"%s^") (access ^"%s^") (address ^"%s^")", name, get_user_userid(id), authid, AuthData, sflags, ip)
		}
		else 
		{
		
			admins_lookup(index,AdminProp_Password,Password,sizeof(Password)-1);

			if (equal(password, Password))
			{
				result |= 12
				set_user_flags(id, Access)
				
				new sflags[32]
				get_flags(Access, sflags, 31)
				
				log_amx("Login: ^"%s<%d><%s><>^" became an admin (account ^"%s^") (access ^"%s^") (address ^"%s^")", name, get_user_userid(id), authid, AuthData, sflags, ip)
			} 
			else 
			{
				result |= 1
				
				if (Flags & FLAG_KICK)
				{
					result |= 2
					log_amx("Login: ^"%s<%d><%s><>^" kicked due to invalid password (account ^"%s^") (address ^"%s^")", name, get_user_userid(id), authid, AuthData, ip)
				}
			}
		}
	}
	else if (get_pcvar_float(amx_mode) == 2.0)
	{
		result |= 2
	} 
	else 
	{
		new defaccess[32]
		
		get_pcvar_string(amx_default_access, defaccess, 31)
		
		if (!strlen(defaccess))
		{
			copy(defaccess, 32, "z")
		}
		
		new idefaccess = read_flags(defaccess)
		
		if (idefaccess)
		{
			result |= 8
			set_user_flags(id, idefaccess)
		}
	}
	
	return result
}

accessUser(id, name[] = "")
{
	remove_user_flags(id)
	
	new userip[32], userauthid[32], password[32], passfield[32], username[32]
	
	get_user_ip(id, userip, 31, 1)
	get_user_authid(id, userauthid, 31)
	
	if (name[0])
	{
		copy(username, 31, name)
	}
	else
	{
		get_user_name(id, username, 31)
	}
	
	get_pcvar_string(amx_password_field, passfield, 31)
	get_user_info(id, passfield, password, 31)
	
	new result = getAccess(id, username, userauthid, userip, password)
	
	if (result & 1)
	{
		client_cmd(id, "echo ^"* %L^"", id, "INV_PAS")
	}
	
	if (result & 2)
	{
		client_cmd(id, "%s", g_cmdLoopback)
		return PLUGIN_HANDLED
	}
	
	if (result & 4)
	{
		client_cmd(id, "echo ^"* %L^"", id, "PAS_ACC")
	}
	
	if (result & 8)
	{
		client_cmd(id, "echo ^"* %L^"", id, "PRIV_SET")
	}
	
	return PLUGIN_CONTINUE
}

public client_infochanged(id)
{
	if (!is_user_connected(id) || !get_pcvar_num(amx_mode))
	{
		return PLUGIN_CONTINUE
	}

	new newname[32], oldname[32]
	
	get_user_name(id, oldname, 31)
	get_user_info(id, "name", newname, 31)

	if (g_CaseSensitiveName[id])
	{
		if (!equal(newname, oldname))
		{
			accessUser(id, newname)
		}
	}
	else
	{
		if (!equali(newname, oldname))
		{
			accessUser(id, newname)
		}
	}
	return PLUGIN_CONTINUE
}

public ackSignal(id)
{
	server_cmd("kick #%d ^"%L^"", get_user_userid(id), id, "NO_ENTRY")
	return PLUGIN_HANDLED
}

public client_authorized(id)
	return get_pcvar_num(amx_mode) ? accessUser(id) : PLUGIN_CONTINUE

public client_putinserver(id)
{
	if (!is_dedicated_server() && id == 1)
		return get_pcvar_num(amx_mode) ? accessUser(id) : PLUGIN_CONTINUE
	
	#if defined USING_SQL
	if(!is_user_admin(id))
	{
		//new rn_message = get_pcvar_num(amx_rn_message)
		new rn_message = get_cvar_num("amx_rn_message")
		
		if(rn_message == 1)
		{
			set_task(10.0, "RNMessage", id)
		}
	}	
	#endif
	
	return PLUGIN_CONTINUE
}

#if defined USING_SQL
public RNMessage(id)
{
	if(!is_user_admin(id))
	{
		new rn_message_site[128]
		get_cvar_string("amx_rn_message_site", rn_message_site, charsmax(rn_message_site))
		
		set_hudmessage(255, 255, 255, -1.0, 0.60, 0, 6.0, 10.0)
		show_hudmessage(id, "Your nickname is not registered!^n^nFor registering, type in your console^nregister <email> <password>^nor go to %s", rn_message_site)
		
		client_cmd(id,"spk ^"vox/warning _comma unauthorized access^"")
		
		set_task(get_cvar_float("amx_rn_message_time"), "RNMessage", id)
	}
}

public RNRegister(id, level, cid)
{
	if (!cmd_access(id, level, cid, 2))
	{
		return PLUGIN_HANDLED
	}
	
	if (get_cvar_num("amx_rn_user_reg") == 0)
	{
		client_print(id, print_console, "[RN] New user registration is closed.");
		#if defined RN_DEBUG
			server_print("[RN] New user registration is closed.");
		#endif
		
		return PLUGIN_HANDLED;
	}
	
	// allow only one account at a time to be created
	if (g_eRegData[REG_ID] > 0)
	{
		client_print(id, print_console, "[RN] System busy. Please try again later.");
	}
	
	new name[33], email[65], pass[65];
	read_argv(1, email, charsmax(email)-1)
	read_argv(2, pass, charsmax(pass)-1)
	get_user_name(id, name, charsmax(name)-1);
	
	new safe_name[128], safe_email[128], safe_pass[128];
	mysql_escape_string(name, safe_name, charsmax(safe_name));
	mysql_escape_string(email, safe_email, charsmax(safe_email));
	mysql_escape_string(pass, safe_pass, charsmax(safe_pass));
	
	if(containi(email, "@")==-1 || containi(email, "<")!=-1 || containi(email, ">")!=-1)
	{
		client_print(id, print_console, "[RN] Invalid e-mail address!")
		#if defined RN_DEBUG
			server_print("[RN] Invalid e-mail address!");
		#endif
		return PLUGIN_HANDLED
	}
	
	if(strlen(pass) < 6)
	{
		client_print(id, print_console, "[RN] Password must have at least 6 characters!")
		#if defined RN_DEBUG
			server_print("[RN] Password must have at least 6 characters!");
		#endif
		return PLUGIN_HANDLED
	}
	
	// ****************************************************************************** 

	g_eRegData[REG_ID] 			= id
	g_eRegData[REG_USER]		= name
	g_eRegData[REG_USER_SAFE]	= safe_name;
	g_eRegData[REG_PASS]		= pass;
	g_eRegData[REG_PASS_SAFE]	= safe_pass;
	g_eRegData[REG_EMAIL]		= email;
	g_eRegData[REG_EMAIL_SAFE]	= safe_email;
	
	new pquery[1024];
	
	formatex(pquery, charsmax(pquery), "SELECT id, login, email FROM `%s` WHERE (`login` = '%s' OR `email` = '%s')", table_prefix("users"), safe_name, safe_email );
	SQL_ThreadQuery(g_Tuple, "RN_Reg_User_Duplicate_Hnd", pquery);
	
	return PLUGIN_HANDLED;
}

public RN_Reg_User_Duplicate_Hnd(failstate, Handle:query, error[], errnum, data[], size)
{
	#if !defined RN_DEBUG
		// Jhon, are you still there ?
		if (!is_user_connected(g_eRegData[REG_ID]))
		{
			enable_registration()
			
			return PLUGIN_HANDLED
		}
	#endif
	
	if (failstate)
	{
		client_print(g_eRegData[REG_ID], print_console, "[RN] Please try again later.")
		
		#if defined RN_DEBUG
			new szQuery[256]
			MySqlX_ThreadError( szQuery, error, errnum, failstate, 10 )
		#endif
		
		enable_registration()
		
		return PLUGIN_HANDLED
	}
	
	if (errnum)
	{
		client_print(g_eRegData[REG_ID], print_console, "[RN] Please try again later.")
		
		#if defined RN_DEBUG
			new szQuery[256]
			MySqlX_ThreadError( szQuery, error, errnum, failstate, 11 )
		#endif
		
		enable_registration()
		
		return PLUGIN_HANDLED
	}
	
	if (SQL_NumResults(query))
	{
		client_print(g_eRegData[REG_ID], print_console, "[RN] User and/or email has been used by someone else.")
		
		#if defined RN_DEBUG
			server_print("[RN] User and/or email has been used by someone else.");
		#endif
		
		enable_registration()
		
		return PLUGIN_HANDLED
	}
	
	#if defined RN_DEBUG
		server_print("[RN] User %s can register", g_eRegData[REG_USER]);
	#endif
	
	new pquery[1024], activation_key[25]
	new register_date = get_systime()
	
	random_str(activation_key, charsmax(activation_key))
	
	formatex(pquery, charsmax(pquery), "\
		INSERT INTO `%s` \
			(`login`, `password`, `email`, `register_date`, `active`, `activation_key`, `account_flags`, `last_login`, `passwd_type`) \
		VALUES \
			('%s', '%s', '%s', '%d', '1', '%s', 'a', '0', '0'); ", 
		table_prefix("users"), 
			g_eRegData[REG_USER_SAFE], g_eRegData[REG_PASS_SAFE], g_eRegData[REG_PASS_SAFE], register_date, activation_key
	);
	
	SQL_ThreadQuery(g_Tuple, "RN_Reg_User_Insert_Acc_Hnd", pquery);
	
	return PLUGIN_HANDLED
}

public RN_Reg_User_Insert_Acc_Hnd(failstate, Handle:query, error[], errnum, data[], size)
{
	if (failstate)
	{
		client_print(g_eRegData[REG_ID], print_console, "[RN] Please try again later.")
		
		#if defined RN_DEBUG
			new szQuery[256]
			MySqlX_ThreadError( szQuery, error, errnum, failstate, 10 )
		#endif
		
		enable_registration()
		
		return PLUGIN_HANDLED
	}
	
	if (errnum)
	{
		client_print(g_eRegData[REG_ID], print_console, "[RN] Please try again later.")
		
		#if defined RN_DEBUG
			new szQuery[256]
			MySqlX_ThreadError( szQuery, error, errnum, failstate, 11 )
		#endif
		
		enable_registration()
		
		return PLUGIN_HANDLED
	}
	
	new user_id			= SQL_GetInsertId(query)
	new rn_group_id		= get_cvar_num("amx_rn_groupid")
	new rn_account_type	= get_cvar_num("amx_rn_account_type")
	new rn_server_id	= get_cvar_num("amx_rn_serverid");
	
	new pquery[1024]
	
	if(rn_account_type == 0)
	{
		formatex(pquery, charsmax(pquery), "INSERT INTO `%s` (`user_ID`, `server_ID`, `group_ID`) VALUES ('%d', '0', '%d')", 
			table_prefix("users_access"), 
				user_id, rn_group_id
		);
	}
	else
	{
		formatex(pquery, charsmax(pquery), "INSERT INTO `%s` (`user_ID`, `server_ID`, `group_ID`) VALUES ('%d', %d, '%d')", 
			table_prefix("users_access"), 
				user_id, rn_server_id, rn_group_id
		);
	}
	
	SQL_ThreadQuery(g_Tuple, "RN_Reg_User_Insert_Grp_Hnd", pquery);
	
	return PLUGIN_HANDLED
}

public RN_Reg_User_Insert_Grp_Hnd(failstate, Handle:query, error[], errnum, data[], size)
{
	new password_field[32]
	get_cvar_string("amx_password_field", password_field, 31)
	
	if (failstate)
	{
		client_print(g_eRegData[REG_ID], print_console, "[RN] Please try again later.")
		
		#if defined RN_DEBUG
			new szQuery[256]
			MySqlX_ThreadError( szQuery, error, errnum, failstate, 10 )
		#endif
		
		enable_registration()
		
		return PLUGIN_HANDLED
	}
	
	if (errnum)
	{
		client_print(g_eRegData[REG_ID], print_console, "[RN] Please try again later.")
		
		#if defined RN_DEBUG
			new szQuery[256]
			MySqlX_ThreadError( szQuery, error, errnum, failstate, 11 )
		#endif
		
		enable_registration()
		
		return PLUGIN_HANDLED
	}
	
	client_print(g_eRegData[REG_ID], print_console, "Your account is now registered!")
	client_print(g_eRegData[REG_ID], print_console, "Write the next line in your console, or you will be kicked in 10 seconds:")
	client_print(g_eRegData[REG_ID], print_console, "setinfo %s %s", password_field, g_eRegData[REG_PASS])
	
	enable_registration()
	
	set_task(10.0, "cmdReload")
	
	return PLUGIN_HANDLED
}

enable_registration()
{
	g_eRegData[REG_ID] = 0;
}

/**
 * Deal with errors
 */
MySqlX_ThreadError(szQuery[], error[], errnum, failstate, id) {
	if (failstate == TQUERY_CONNECT_FAILED) {
		log_amx("[RN] DB connection failed")
	} else if (failstate == TQUERY_QUERY_FAILED) {
		log_amx("[RN] Query failed!")
	}
	log_amx("[RN] Threaded Query Error on ID: #%d", id)
	log_amx("[RN] Error message: %s (%d)", error, errnum);
	log_amx("[RN] Query statement: %s", szQuery);
}
#endif
/* AMXX-Studio Notes - DO NOT MODIFY BELOW HERE
*{\\ rtf1\\ ansi\\ deff0{\\ fonttbl{\\ f0\\ fnil Tahoma;}}\n\\ viewkind4\\ uc1\\ pard\\ lang1033\\ f0\\ fs16 \n\\ par }
*/
