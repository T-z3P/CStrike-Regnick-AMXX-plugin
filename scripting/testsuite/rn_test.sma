#include <amxmodx>
#include <amxmisc>
#include <sqlx>
#include "../include/regnick.inc"

new g_TestNum

public plugin_init()
{
	register_plugin("CStrike-Regnick test", "1.0", "Gentle Software Solutions")
	
	register_srvcmd("rn_test_mysql_quote", "RN_Test_MySQL_Quote")
	register_srvcmd("rn_test_mysql_escape", "RN_Test_MySQL_Escape")
	register_srvcmd("rn_test_mysql_table_prefix", "RN_Test_MySQL_Table_Prefix")
	register_srvcmd("rn_test_random_string", "RN_Random_String")
	
	g_TestNum++
	set_task(7.0, "RunAllTests")
}

public RunAllTests()
{
	server_print("------------------------------------------------------------------")
	server_print("CStrike-Regnick Test Suite")
	server_print("-------")
	
	RN_Test_MySQL_Quote()
	g_TestNum++
	
	RN_Test_MySQL_Escape()
	g_TestNum++
	
	RN_Test_MySQL_Table_Prefix
	g_TestNum++
	
	RN_Random_String
	g_TestNum++
	
	server_print("------------------------------------------------------------------")
}

// ------------------------------------------------------------------------------------------------

public RN_Random_String()
{
	new str_small[6], str_med[11], str_large[31];
	random_str(str_small, charsmax(str_small))
	random_str(str_med, charsmax(str_med))
	random_str(str_large, charsmax(str_large))
	
	server_print("[Test #%d] Random string (length %d): %s", g_TestNum, charsmax(str_small), str_small)
	server_print("[Test #%d] Random string (length %d): %s", g_TestNum, charsmax(str_med), str_med)
	server_print("[Test #%d] Random string (length %d): %s", g_TestNum, charsmax(str_large), str_large)
}

public RN_Test_MySQL_Table_Prefix()
{
	server_print("[Test #%d] Table prefix 'users': %s", g_TestNum, table_prefix("users"))
	server_print("[Test #%d] Table prefix 'groups': %s", g_TestNum, table_prefix("groups"))
	server_print("[Test #%d] Table prefix 'gentle': %s", g_TestNum, table_prefix("gentle"))
}

/**
 * Test string quoting
 */
public RN_Test_MySQL_Quote()
{
	new error[128], type[12], errno;
	
	new Handle:info = SQL_MakeStdTuple()
	new Handle:sql = SQL_Connect(info, errno, error, 127)
	
	SQL_GetAffinity(type, 11)
	
	if (sql == Empty_Handle)
	{
		server_print("Connect failure: [%d] %s", errno, error)
		return
	}
	
	new buffer[500]
	
	SQL_QuoteString(sql, buffer, sizeof(buffer)-1, "Hi y'all! C\lam `\0")
	
	server_print("[Test #%d] Quote string: %s", g_TestNum, buffer)
	
	SQL_FreeHandle(sql)
	SQL_FreeHandle(info)
}

public RN_Test_MySQL_Escape()
{
	new str[] = "Hi y'all! C\lam `\0"
	
	new safe_str[128];
	mysql_escape_string(str, safe_str, charsmax(safe_str));

	server_print("[Test #%d] Escape string: %s", g_TestNum, safe_str)
}