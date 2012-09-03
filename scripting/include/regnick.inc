/* CStrike-Regnick helper functions
 *
 * @copyright   (c) 2011 - 2012 Gentle Software Solutions 
 * @license     http://opensource.org/licenses/gpl-2.0.php GNU Public License 
 * @link        http://www.gentle.ro/ 
 */

/**
 * Generate a random string
 * 
 * @access	private
 * @param	array	output
 * @param	int		len
 * @return	string
 */
random_str(output[], len)
{
	for(new i=0; i<len; i++)
	{
		output[i] = random_num('0', '9');
	}
    
	output[len]=EOS;
}
 
/**
 * Add prefix to specified table
 *
 * @access	public
 * @param	array	name	Table name
 * @return	string
 */
public table_prefix(name[])
{
	new prefix[32], temp[128];
	get_cvar_string("amx_sql_table_prefix", prefix, 31);
	
	format(temp, 127, "%s%s", prefix, name);
	
	return temp;
}

/**
 * Get escaped server hostname.
 *
 * Safe to be used in MySQL query.
 *
 * <code>
 *   new server_name[200]
 *   mysql_escape_hostname(server_name, charsmax(server_name));
 * </code>
 *
 * @param	array   dest
 * @param	int     len
 * @return	void
 */
stock void:mysql_escape_hostname(dest[], len)
{
	new name[256];
	get_cvar_string("hostname", name, charsmax(name))
	mysql_escape_string(name, dest, len);
}

/**
 * Get escaped username.
 *
 * Safe to be used in MySQL query.
 *
 * <code>
 *   new admin_nick[64]
 *   mysql_escape_username(id, admin_nick, charsmax(admin_nick));
 * </code>
 *
 * @param	int		id		Player ID
 * @param	array   dest
 * @param	int     len
 * @return	void
 */
stock void:mysql_escape_username(id, dest[], len)
{
	new name[128];
	get_user_name(id,name,127);
	mysql_escape_string(name,dest,len);
}

/**
 * Escape a string to prevent MySQL injection
 *
 * <code>
 *   new safe_str[128];
 *   mysql_escape_string(str, safe_str, charsmax(safe_str));
 * </code>
 *
 * @param	array   source
 * @param	array	dest
 * @param	int     len
 * @return	void
 */
stock void:mysql_escape_string(const source[], dest[], len)
{
	copy(dest, len, source);
	
	replace_all(dest,len,"\\","\\\\");
	replace_all(dest,len,"\0","\\0'");
	replace_all(dest,len,"\n","\\n");
	replace_all(dest,len,"\r","\\r");
	replace_all(dest,len,"'","\'");
	replace_all(dest,len,"`","\`");
	replace_all(dest,len,"\x1a","\\x1a");
	replace_all(dest,len,"^"","\^"");
}
