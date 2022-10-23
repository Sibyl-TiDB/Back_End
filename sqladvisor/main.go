package main

import (
	"bytes"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/gin-gonic/gin"
	_ "github.com/go-sql-driver/mysql"
	_ "github.com/mattn/go-sqlite3"
	"github.com/pingcap/parser"
	"github.com/pingcap/parser/ast"
	"github.com/pingcap/parser/format"
	"time"

	driver "github.com/pingcap/parser/test_driver"
	"net/http"
	"strconv"
	"strings"
)

type Table_Info struct {
	tableName string
	aliasName string
	schema    string
	where     []string
	groupBy   []string
	orderBy   []string
}

var currentBinaryOpCnt int = 0
var groupByCnt int = 0
var result = map[string]poor_sql{}

type poor_sql struct {
	Digest      string          `json:"Digest"`
	SqlTxt      string          `json:"SqlTxt"`
	ExecutionDB string          `json:"ExecutionDB"`
	Impact      string          `json:"Impact"`
	Advisors    []advisorResult `json:"Advisors"`
}

type index_info struct {
	ColName string `json:"ColName"`
	Cnt     int    `json:"Cnt"`
}

type advisorResult struct {
	TableName    string       `json:"TableName"`
	IndexCols    []index_info `json:"IndexCols"`
	AdviszedStmt string       `json:"AdviszedStmt"`
	Suggestion   string       `json:"Suggestion"`
	MsgParams    string       `json:"MsgParams"`
}
type GroupByClauseVisitor struct {
	sqlParsedResult map[string]*Table_Info
}
type BinaryOperationExprVisitor struct {
	sqlParsedResult map[string]*Table_Info
}

type ColumnNameVisitor struct {
	sqlParsedResult map[string]*Table_Info
}

type FingerprintVisitor struct {
	sqlTxt          string
	sqlDigest       string
	sqlParsedResult map[string]*Table_Info
}

type TableRefsClauseVisitor struct {
	sqlParsedResult map[string]*Table_Info
}
type TableSourceVisitor struct {
	sqlParsedResult map[string]*Table_Info
}

type TableNameVisitor struct {
	sqlParsedResult map[string]*Table_Info
	alias           string
}

var dbHost *string
var DBPort *int
var Username *string
var dbPwd *string
var database *string

func initSqlLit() {
	db, err := sql.Open("sqlite3", "./foo11.db")
	if err != nil {
		fmt.Errorf("init sqllit error %s", err.Error())
	}

	sql_table := `
    CREATE TABLE IF NOT EXISTS TuningResult(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        Digest VARCHAR(500) NULL,
		Advisors VARCHAR(8000) NULL,
        created INTEGER NULL
    )`
	db.Exec(sql_table)
}
func SaveResultsToDB(result poor_sql) {
	defer func() {
		err := recover()
		fmt.Println(err)
		fmt.Println("释放数据库连接...")
	}()
	db, err := sql.Open("sqlite3", "./foo11.db")
	if err != nil {
		fmt.Errorf("Open sqllit error %s", err.Error())
	}
	digest := result.Digest
	bits, err := json.Marshal(result)
	if err != nil {
		return
	}
	advisor := string(bits)
	stmt, err := db.Prepare("INSERT INTO TuningResult(Digest,Advisors, created) values(?,?,?)")
	_, err = stmt.Exec(digest, advisor, time.Now().Unix())
	if err != nil {
		fmt.Errorf("Save result to sqllit error %s", err.Error())
	}
}

//	type TuningResultsList struct {
//		Digest string `json:"Digest"`
//		Tunning
//	}
type TuningResults struct {
	Reslusts []string `json:"Reslusts"`
}

func CheckTuningResultIfExists(digest string) bool {
	db, err := sql.Open("sqlite3", "./foo11.db")
	if err != nil {
		fmt.Errorf("QueryTuningResultsByTime:Open sqllit error %s", err.Error())
	}
	t := time.Now().Add(time.Minute * -60)
	rows, err := db.Query("select   count(*) from TuningResult where created>=? and Digest=?", t.Unix(), digest)
	if err == nil {
		for rows.Next() {
			cnt := 0
			rows.Scan(&cnt)
			if cnt > 0 {
				return true
			}
		}
	}
	return false
}

func QueryTuningResultByDigest(digest string) poor_sql {
	db, err := sql.Open("sqlite3", "./foo11.db")
	if err != nil {
		fmt.Errorf("QueryTuningResultsByTime:Open sqllit error %s", err.Error())
	}
	rows, err := db.Query("select advisors from TuningResult where Digest=? order by created desc limit 1 ", digest)
	if err != nil {
		fmt.Errorf("QueryTuningResultsByTime:Query error %s", err.Error())
	}
	psql := poor_sql{}
	for rows.Next() {
		str := ""
		rows.Scan(&str)

		json.Unmarshal([]byte(str), &psql)
	}
	return psql
}
func QueryTuningResultsInOneHour() []poor_sql {
	db, err := sql.Open("sqlite3", "./foo11.db")
	if err != nil {
		fmt.Errorf("QueryTuningResultsByTime:Open sqllit error %s", err.Error())
	}
	t := time.Now().Add(time.Minute * -60)
	rows, err := db.Query("select   advisors from TuningResult where created>=?", t.Unix())
	if err != nil {
		fmt.Errorf("QueryTuningResultsByTime:Query error %s", err.Error())
	}
	results := make([]poor_sql, 0, 500)
	for rows.Next() {
		str := ""
		rows.Scan(&str)
		psql := poor_sql{}
		json.Unmarshal([]byte(str), &psql)
		results = append(results, psql)
	}
	return results
}
func (f *TableNameVisitor) Enter(n ast.Node) (node ast.Node, skipChildren bool) {
	if v, ok := n.(*ast.TableName); ok {
		var key string
		var tbl *Table_Info
		if f.alias == "" {
			if v.Schema.O == "" {
				key = v.Name.O
			} else {
				key = v.Schema.O + ":" + v.Name.O
			}
			tbl = &Table_Info{where: make([]string, 0, 10), groupBy: make([]string, 0, 10), orderBy: make([]string, 0, 10)}
		} else {
			key = v.Schema.O + ":" + v.Name.O + ":" + f.alias
			tbl = f.sqlParsedResult[f.alias]
		}
		tbl.schema = v.Schema.O
		tbl.tableName = v.Name.O
		f.sqlParsedResult[key] = tbl
		if f.alias != "" {
			f.sqlParsedResult[f.alias] = tbl
		}
	}
	return n, false

}

func (f *TableNameVisitor) Leave(n ast.Node) (node ast.Node, skipChildren bool) {
	return n, false
}
func (f *TableSourceVisitor) Enter(n ast.Node) (node ast.Node, skipChildren bool) {
	if v, ok := n.(*ast.TableSource); ok {
		alias := ""
		if v.AsName.O != "" {
			alias = v.AsName.O
			tblInfor := Table_Info{where: make([]string, 0, 10), groupBy: make([]string, 0, 10), orderBy: make([]string, 0, 10)}
			tblInfor.aliasName = alias
			f.sqlParsedResult[alias] = &tblInfor
		}
		n.Accept(&TableNameVisitor{alias: alias, sqlParsedResult: f.sqlParsedResult})
	}

	return n, false
}

func (f *TableRefsClauseVisitor) Leave(n ast.Node) (node ast.Node, ok bool) {
	return n, true
}

func (f *TableSourceVisitor) Leave(n ast.Node) (node ast.Node, ok bool) {
	return n, true
}

func (f *TableRefsClauseVisitor) Enter(n ast.Node) (node ast.Node, skipChildren bool) {
	n.Accept(&TableSourceVisitor{f.sqlParsedResult})
	return n, false
}

func contains(s []string, e string) bool {
	for _, a := range s {
		if a == e {
			return true
		}
	}
	return false
}

func (f *ColumnNameVisitor) Enter(n ast.Node) (node ast.Node, skipChildren bool) {
	if currentBinaryOpCnt > 0 {
		if v, ok := n.(*ast.ColumnName); ok {
			if v.Table.O != "" {
				alias := v.Table.O
				column := v.Name.O
				if alias != "" && !contains(f.sqlParsedResult[alias].where, column) {
					f.sqlParsedResult[alias].where = append(f.sqlParsedResult[alias].where, column)
				}
			} else {
				column := v.Name.O
				//TODO
				for _, v := range f.sqlParsedResult {
					if !contains(v.where, column) {
						v.where = append(v.where, column)
					}
				}
			}
		}
	}
	return n, false
}

func (f *ColumnNameVisitor) Leave(n ast.Node) (node ast.Node, ok bool) {
	return n, true
}

func (f *GroupByClauseVisitor) Enter(n ast.Node) (node ast.Node, skipChildren bool) {
	if v, ok := n.(*ast.GroupByClause); ok {
		groupByCnt = groupByCnt + 1
		if len(v.Items) > 0 {
			for _, item := range v.Items {
				if v1, ok1 := item.Expr.(*ast.ColumnNameExpr); ok1 {
					alias := v1.Name.Table.O
					columnName := v1.Name.Name.O
					if alias != "" {
						f.sqlParsedResult[alias].groupBy = append(f.sqlParsedResult[alias].groupBy, columnName)
					} else {
						for _, val := range f.sqlParsedResult {
							val.groupBy = append(val.groupBy, columnName)
						}
					}
				}
			}
		}
	}
	return n, false
}

func (f *GroupByClauseVisitor) Leave(n ast.Node) (node ast.Node, ok bool) {
	if _, ok := n.(*ast.GroupByClause); ok {
		groupByCnt = groupByCnt - 1
	}
	return n, true
}

func (f *BinaryOperationExprVisitor) Enter(n ast.Node) (node ast.Node, skipChildren bool) {
	if v, ok := n.(*ast.BinaryOperationExpr); ok {
		currentBinaryOpCnt = currentBinaryOpCnt + 1
		v.Accept(&ColumnNameVisitor{f.sqlParsedResult})
	}
	return n, false
}

func (f *BinaryOperationExprVisitor) Leave(n ast.Node) (node ast.Node, ok bool) {
	if _, ok := n.(*ast.BinaryOperationExpr); ok {
		currentBinaryOpCnt = currentBinaryOpCnt - 1
	}
	return n, true
}

func (f *FingerprintVisitor) Enter(n ast.Node) (node ast.Node, skipChildren bool) {
	if v2, ok2 := n.(*ast.BinaryOperationExpr); ok2 {
		v2.Accept(&BinaryOperationExprVisitor{f.sqlParsedResult})
	}
	// 当访问到ValueExpr 时，只需要将ValueExpr的值替换掉就行
	if v2, ok2 := n.(*ast.TableRefsClause); ok2 {
		v2.Accept(&TableRefsClauseVisitor{f.sqlParsedResult})
		//fmt.Printf(v2.Text())
	}
	if v2, ok2 := n.(*ast.GroupByClause); ok2 {
		v2.Accept(&GroupByClauseVisitor{f.sqlParsedResult})
	}
	if v, ok := n.(*driver.ValueExpr); ok {
		v.Type.Charset = ""
		v.SetValue([]byte("?"))
	}
	return n, false
}

func (f *FingerprintVisitor) Leave(n ast.Node) (node ast.Node, ok bool) {
	return n, true
}
func parse(sql string, visitor *FingerprintVisitor) (*ast.StmtNode, error) {
	p := parser.New()
	formatedSql := ""
	if strings.Contains(sql, "(") {
		sts := strings.Split(sql, "(")
		for i, str := range sts {
			if i == 0 {
				formatedSql = strings.TrimSpace(str)
			} else {
				formatedSql = formatedSql + "(" + strings.TrimSpace(str)
			}
		}
	} else {
		formatedSql = sql
	}
	stmtNode, err := p.ParseOneStmt(formatedSql, "", "")
	if err != nil {
		return nil, err
	}
	stmtNode.Accept(visitor)
	buf := new(bytes.Buffer)
	restoreCtx := format.NewRestoreCtx(format.RestoreKeyWordUppercase|format.RestoreNameBackQuotes, buf)
	err = stmtNode.Restore(restoreCtx)
	if nil != err {
		// 省略错误处理
		return nil, err
	}
	fmt.Println(buf.String())
	return &stmtNode, nil
}

func getDBConnStr() string {
	return fmt.Sprintf("%s:%s@tcp(%s:%d)/%s?charset=utf8", *Username, *dbPwd, *dbHost, *DBPort, *database)
}
func quryDB(sqlTxt string) ([]index_info, error) {
	db, err := sql.Open("mysql", getDBConnStr())
	defer func() {
		if err := recover(); err != nil {
			fmt.Println(err)
		}
		db.Close()
	}()
	if err != nil {
		fmt.Errorf("open db failed. %s", err)
		return nil, err
	}
	rows, err := db.Query(sqlTxt)
	if err != nil {
		fmt.Errorf("failed to exectue sql. %s", err)
		return nil, err
	}
	idxCols := make([]index_info, 0, 10)
	for rows.Next() {
		idxInfo := index_info{}
		rows.Scan(&idxInfo.ColName, &idxInfo.Cnt)
		idxCols = append(idxCols, idxInfo)
		fmt.Printf("the value is %v ", idxInfo)
	}

	return idxCols, nil
}

// TODO need to add logic to check if the seq of index right
func existIndexesByCols(schema, tblName string, cols []string) (bool, error) {
	db, err := sql.Open("mysql", getDBConnStr())
	defer db.Close()
	if err != nil {
		fmt.Errorf("open db failed. %s", err)
	}
	colsStr := ""
	colseq := 0
	colPositionMap := make(map[string]int)
	for i, item := range cols {
		colseq = colseq + 1
		colPositionMap[strings.ToUpper(item)] = colseq
		if i > 0 {
			colsStr = colsStr + ",'" + item + "'"
		} else {
			colsStr = colsStr + "'" + item + "'"
		}
	}
	sqlTxt := fmt.Sprintf("select KEY_NAME,SEQ_IN_INDEX,COLUMN_NAME  from INFORMATION_SCHEMA.TIDB_INDEXES where  table_schema='%s' and upper(TABLE_NAME)=upper('%s') and upper(COLUMN_NAME) in(%s) order by  KEY_NAME,SEQ_IN_INDEX", schema, tblName, strings.ToUpper(colsStr))
	rows, err := db.Query(sqlTxt)
	if err != nil {
		fmt.Errorf("failed to exectue sql. %s", err)
		return false, err
	}
	seqInIdx := -1
	preKeyName := ""
	goodCnt := 0
	keyName := ""
	colName := ""
	for rows.Next() {
		rows.Scan(&keyName, &seqInIdx, &colName)
		if preKeyName == "" {
			preKeyName = keyName
		} else if preKeyName != keyName {
			if goodCnt == colseq {
				return true, nil
			} else {
				goodCnt = 0
			}
		}
		if colPositionMap[colName] == seqInIdx {
			goodCnt = goodCnt + 1
			continue
		}
	}
	return goodCnt == colseq, nil
}

type SlowQuerySummary struct {
	RowNum       int     `json:"RowNum"`
	ExeTime      int     `json:"ExeTime"`
	QueryText    string  `json:"QueryText"`
	Time         float64 `json:"Time"`
	Digest       string  `json:"Digest"`
	TimeAt       string  `json:"TimeAt"`
	Connection   string  `json:"Connection"`
	DB           string  `json:"DB"`
	TiDBInstance string  `json:"TiDBInstance"`
}

func GetSlowQuerySummary(tidbSqlTxt string) []SlowQuerySummary {
	db, err := sql.Open("mysql", getDBConnStr())
	defer db.Close()
	if err != nil {
		fmt.Errorf("open db failed. %s", err)
	}
	rows, err := db.Query(tidbSqlTxt)
	slowQueries := make([]SlowQuerySummary, 0, 1000)
	for rows.Next() {
		var a, b, c, d string
		sqlQueryInfo := SlowQuerySummary{}
		rows.Scan(&a, &b, &c, &d, &sqlQueryInfo.Digest, &sqlQueryInfo.Connection, &sqlQueryInfo.TimeAt, &sqlQueryInfo.DB, &sqlQueryInfo.TiDBInstance)
		sqlQueryInfo.RowNum, _ = strconv.Atoi(a)
		sqlQueryInfo.ExeTime, _ = strconv.Atoi((strings.Split(b, "."))[0])
		sqlQueryInfo.QueryText = c
		sqlQueryInfo.Time, _ = strconv.ParseFloat(d, 64)

		slowQueries = append(slowQueries, sqlQueryInfo)
	}
	return slowQueries
}

func GetSlowQueryExectionsInOneHour(tidbSqlTxt string) int {
	db, err := sql.Open("mysql", getDBConnStr())
	defer db.Close()
	if err != nil {
		fmt.Errorf("open db failed. %s", err)
	}
	rows, err := db.Query(tidbSqlTxt)
	cnt := 0
	for rows.Next() {
		rows.Scan(&cnt)
	}
	return cnt
}

func GetTopSlowQuery(ctx *gin.Context) {
	defer func() {
		err := recover()
		fmt.Println(err)
		fmt.Println("释放数据库连接...")
	}()

	tidbSqlTxt := "select row_num, exe_time as exeTime, Query as queryText   ,queryTime,DIGEST, connection, UNIX_TIMESTAMP(timeAt) as timeAt ,db11,TidbInstance from ( select row_number()over(partition by DATE_FORMAT(Time,'%y-%m-%d %H:%i')  order by Query_time desc) as row_num, UNIX_TIMESTAMP(DATE_FORMAT(Time,'%Y-%m-%d %H:%i:00')) as exe_time,DIGEST ,Time as timeAt,Conn_ID as connection,Query, format(Query_time,4) as queryTime ,`DB` as db11,`INSTANCE` as  TidbInstance from INFORMATION_SCHEMA.cluster_slow_query where plan not like '%tiflash%' and Time>SUBDATE(now(),interval 3600 second) and `DB` in ('test') and upper(query) not like '%ANALYZE%' and upper(query) not like '%INFORMATION_SCHEMA%' and upper(query) not like '%INSERT%')  ss where row_num<=10 order by  exe_time,queryTime desc"
	tiflashSqlTxt := "select row_num, exe_time as exeTime, Query as queryText   ,queryTime,DIGEST, connection, UNIX_TIMESTAMP(timeAt) as timeAt ,db11,TidbInstance from ( select row_number()over(partition by DATE_FORMAT(Time,'%y-%m-%d %H:%i')  order by Query_time desc) as row_num, UNIX_TIMESTAMP(DATE_FORMAT(Time,'%Y-%m-%d %H:%i:00')) as exe_time,DIGEST ,Time as timeAt,Conn_ID as connection,Query, format(Query_time,4) as queryTime ,`DB` as db11,`INSTANCE` as  TidbInstance from INFORMATION_SCHEMA.cluster_slow_query where plan  like '%tiflash%' and Time>SUBDATE(now(),interval 3600 second) and `DB` in ('test') and upper(query) not like '%ANALYZE%' and upper(query) not like '%INFORMATION_SCHEMA%' and upper(query) not like '%INSERT%') ss where row_num<=10 order by  exe_time,queryTime desc"
	tidbSlowQueryList := GetSlowQuerySummary(tidbSqlTxt)
	tiflashSlowQueryList := GetSlowQuerySummary(tiflashSqlTxt)

	ctx.Header("Access-Control-Allow-Origin", "*")  // 这是允许访问所有域
	ctx.Header("Access-Control-Allow-Methods", "*") //服务器支持的所有跨域请求的方法,为了避免浏览次请求的多次'预检'请求

	ctx.JSON(http.StatusOK, gin.H{ //以json格式输出
		"tidbSlowQueryList":    tidbSlowQueryList,
		"tiflashSlowQueryList": tiflashSlowQueryList,
	})
}

func GetSlowQueriesByDigest(ctx *gin.Context) {
	digest := ctx.Query("digest")
	sqlTxt := "select row_num, exe_time as exeTime, Query as queryText   ,queryTime,DIGEST, connection, UNIX_TIMESTAMP(timeAt) as timeAt ,db11,TidbInstance from ( select row_number()over(partition by DATE_FORMAT(Time,'%y-%m-%d %H:%i')  order by Query_time desc) as row_num, UNIX_TIMESTAMP(DATE_FORMAT(Time,'%Y-%m-%d %H:%i:00')) as exe_time,DIGEST ,Time as timeAt,Conn_ID as connection,Query, format(Query_time,4) as queryTime ,`DB` as db11,`INSTANCE` as  TidbInstance from INFORMATION_SCHEMA.cluster_slow_query where Time>SUBDATE(now(),interval 3600 second)   and DIGEST='" + digest + "' and query not like 'load%') ss where row_num<=10 order by  exe_time,queryTime desc"
	tidbSlowQueryList := GetSlowQuerySummary(sqlTxt)

	ctx.Header("Access-Control-Allow-Origin", "*")  // 这是允许访问所有域
	ctx.Header("Access-Control-Allow-Methods", "*") //服务器支持的所有跨域请求的方法,为了避免浏览次请求的多次'预检'请求

	ctx.JSON(http.StatusOK, gin.H{ //以json格式输出
		"tidbSlowQueryList": tidbSlowQueryList,
	})
}

func GetTunningResults(ctx *gin.Context) {
	ctx.Header("Access-Control-Allow-Origin", "*")  // 这是允许访问所有域
	ctx.Header("Access-Control-Allow-Methods", "*") //服务器支持的所有跨域请求的方法,为了避免浏览次请求的多次'预检'请求
	ctx.JSON(http.StatusOK, gin.H{                  //以json格式输出
		"tuningResults": QueryTuningResultsInOneHour(),
	})
}

func GetTunningResultDetail(ctx *gin.Context) {
	ctx.Header("Access-Control-Allow-Origin", "*")  // 这是允许访问所有域
	ctx.Header("Access-Control-Allow-Methods", "*") //服务器支持的所有跨域请求的方法,为了避免浏览次请求的多次'预检'请求
	digest := ctx.Query("digest")
	ctx.JSON(http.StatusOK, gin.H{ //以json格式输出
		"tuningResults": QueryTuningResultByDigest(digest),
	})
}

func SqlStmtTuning() map[string]poor_sql {
	defer func() {
		err := recover()
		fmt.Println(err)
		fmt.Println("释放数据库连接...")
	}()
	tidbSqlTxt := "select row_num, exe_time as exeTime, Query as queryText,queryTime,DIGEST, connection, UNIX_TIMESTAMP(timeAt) as timeAt ,db11,tidbInstance from ( select row_number()over(partition by DATE_FORMAT(Time,'%y-%m-%d %H:%i')  order by Query_time desc) as row_num, UNIX_TIMESTAMP(DATE_FORMAT(Time,'%Y-%m-%d %H:%i:00')) as exe_time,DIGEST ,Time as timeAt,Conn_ID as connection,Query, format(Query_time,4) as queryTime ,`DB` as db11,`INSTANCE` as  tidbInstance from INFORMATION_SCHEMA.cluster_slow_query where plan not like '%tiflash%' and upper(query) not like '%INFORMATION_SCHEMA%' and Time>SUBDATE(now(),interval 3600 second) and query not like 'load%') ss where row_num<=10 order by  exe_time,queryTime desc"
	tidbSlowQueryList := GetSlowQuerySummary(tidbSqlTxt)
	for _, v := range tidbSlowQueryList {
		if CheckTuningResultIfExists(v.Digest) {
			continue
		}
		if _, ok := result[v.Digest]; !ok {
			var sqlParsedResult = make(map[string]*Table_Info)
			cnt := GetSlowQueryExectionsInOneHour("select count(*) from  INFORMATION_SCHEMA.cluster_slow_query where digest='" + v.Digest + "' and Time>SUBDATE(now(),interval 3600 second)")
			tuningResults := tuningSqlStmt(v.QueryText, v.DB, v.Digest, sqlParsedResult)
			//if _, ok := result[v.Digest]; !ok {
			poorSql := poor_sql{SqlTxt: v.QueryText, Digest: v.Digest, ExecutionDB: v.DB, Advisors: tuningResults}
			impact := 0
			for _, item := range tuningResults {
				if item.Suggestion == "MISS_WHERE_CLAUSE_WITHOUT_AP_FUC" {
					impact = impact + 0
				} else if item.Suggestion == "MISS_WHERE_CLAUSE_WITH_AP_FUC" {
					impact = impact + 150 + cnt
					break
				} else if item.Suggestion == "MISS_INDEX" {
					impact = impact + 250 + cnt
					break
				}
			}
			poorSql.Impact = strconv.Itoa(impact) + "%"
			SaveResultsToDB(poorSql)
		}
	}
	return result
}

func doingSqlStmtTuning(ctx *gin.Context) {
	result = SqlStmtTuning()
	ctx.Header("Access-Control-Allow-Origin", "*")  // 这是允许访问所有域
	ctx.Header("Access-Control-Allow-Methods", "*") //服务器支持的所有跨域请求的方法,为了避免浏览次请求的多次'预检'请求
	ctx.JSON(http.StatusOK, gin.H{                  //以json格式输出
		"sqlTuningResults": result,
	})
}

func formatedSql(sqlTxt string) string {
	formatedSql := sqlTxt
	if strings.Contains(sqlTxt, "(") {
		sts := strings.Split(sqlTxt, "(")
		for i, str := range sts {
			if i == 0 {
				formatedSql = strings.TrimSpace(str)
			} else {
				formatedSql = formatedSql + "(" + strings.TrimSpace(str)
			}
		}
	}
	return formatedSql
}

func tuningSqlStmt(sqltxt string, schemaDB string, sqlDigest string, sqlParsedResult map[string]*Table_Info) []advisorResult {
	doneMap := make(map[string]bool)
	advisorResults := make([]advisorResult, 0, 5)
	visitor := &FingerprintVisitor{sqlTxt: sqltxt, sqlDigest: sqlDigest, sqlParsedResult: sqlParsedResult}
	_, err := parse(sqltxt, visitor)
	if err != nil {
		fmt.Printf("parse error: %v\n", err.Error())
		advisor := advisorResult{Suggestion: "SQL_CAN_NOT_PARSE_NEED_SUPPORT"}
		advisorResults := append(advisorResults, advisor)
		return advisorResults
	}

	for key := range visitor.sqlParsedResult {
		tblInfo := visitor.sqlParsedResult[key]
		if tblInfo.tableName == "" {
			continue
		}
		wheres := tblInfo.where
		tblFulName := ""
		if tblInfo.schema != "" {
			tblFulName = "`" + tblInfo.schema + "`." + "`" + tblInfo.tableName + "`"
		} else {
			tblFulName = "`" + schemaDB + "`.`" + tblInfo.tableName + "`"
		}
		if tblInfo.aliasName == "" {
			if doneMap[tblInfo.schema+":"+tblInfo.tableName] == true {
				continue
			}
			doneMap[tblInfo.schema+":"+tblInfo.tableName] = true
		} else {
			if doneMap[tblInfo.schema+":"+tblInfo.tableName+":"+tblInfo.aliasName] == true {
				continue
			}
			doneMap[tblInfo.schema+":"+tblInfo.tableName+":"+tblInfo.aliasName] = true
		}

		if tblInfo.where == nil || len(tblInfo.where) == 0 {
			var advisor advisorResult
			fsql := formatedSql(sqltxt)
			if strings.Contains(strings.ToUpper(fsql), "VARIANCE(") || strings.Contains(strings.ToUpper(fsql), "COUNT(") || strings.Contains(strings.ToUpper(fsql), "MAX(") || strings.Contains(strings.ToUpper(fsql), "MIN(") || strings.Contains(strings.ToUpper(fsql), "SUM(") {
				advisor = advisorResult{TableName: tblFulName, Suggestion: "MISS_WHERE_CLAUSE_WITH_AP_FUC"}
				advisor.AdviszedStmt = "alter table " + tblFulName + " set tiflash replica 1;\n set global tidb_isolation_read_engines='tikv,tiflash,tidb';"
			} else {
				advisor = advisorResult{TableName: tblFulName, Suggestion: "MISS_WHERE_CLAUSE_WITHOUT_AP_FUC"}
			}
			//todo need to add checker
			advisorResults = append(advisorResults, advisor)
			return advisorResults
		}
		ok, err := existIndexesByCols(tblInfo.schema, tblInfo.tableName, tblInfo.where)
		if ok {
			fmt.Printf("Find correct index for the table %s", tblInfo.tableName)
			advisor := advisorResult{TableName: tblFulName, Suggestion: "FOUND_EXSTING_INDEX"}
			advisorResults = append(advisorResults, advisor)
			return advisorResults
		}
		if err != nil {
			fmt.Printf("Find correct index for the table %s", tblInfo.tableName)
			advisor := advisorResult{TableName: tblFulName, Suggestion: "SQL_CAN_NOT_PARSE_NEED_SUPPORT"}
			advisorResults = append(advisorResults, advisor)
			return advisorResults
		}
		innerWithSelect := " select "
		singleCTESelectTmpl := "select '%s' as  col_name ,count(*) as cnt from (select distinct `%s` from cte ) %s_cnt"
		singleCTESelect := ""
		for idx, col := range wheres {
			if idx > 0 {
				innerWithSelect = innerWithSelect + " , `" + col + "`"
				singleCTESelect = singleCTESelect + " union " + fmt.Sprintf(singleCTESelectTmpl, col, col, col)
			} else {
				innerWithSelect = innerWithSelect + " `" + col + "`"
				fmt.Sprintf(singleCTESelect, col)
				singleCTESelect = fmt.Sprintf(singleCTESelectTmpl, col, col, col)
			}
		}
		innerWithSelect = innerWithSelect + " from " + tblFulName + " limit 10000"

		checkSql := fmt.Sprintf("with cte as (%s) select col_name, cnt from (%s) aaaa_ order by cnt desc", innerWithSelect, singleCTESelect)
		indexInfo, sqlErr := quryDB(checkSql)
		if sqlErr != nil {
			advisor := advisorResult{Suggestion: "SQL_CAN_NOT_PARSE_NEED_SUPPORT"}
			advisorResults = append(advisorResults, advisor)
			continue
		}
		advisor := advisorResult{TableName: tblFulName, IndexCols: indexInfo}
		indexStmt := generateIndexSql(tblFulName, indexInfo)
		advisor.AdviszedStmt = indexStmt
		advisor.Suggestion = "MISS_INDEX"
		advisorResults = append(advisorResults, advisor)
		fmt.Printf("%s, the result is %v", tblFulName, indexInfo)
		fmt.Printf("key is : %s\n", key)
	}
	return advisorResults
}

func generateIndexSql(tableName string, indexCols []index_info) string {
	colStr := ""
	idxSufix := ""
	for i, col := range indexCols {
		if strings.ToLower(col.ColName) == "id" {
			continue
		}
		if i == 0 || colStr == "" {
			colStr = col.ColName
			idxSufix = col.ColName
		} else {
			colStr = colStr + "," + col.ColName
			idxSufix = idxSufix + "_" + col.ColName
		}
	}
	return "create index $$$" + idxSufix + "$$$$ on " + tableName + "(" + colStr + ");"
}
func StartBackgroudTunningJob() {
	myTimer := time.NewTimer(time.Second * 10)
	i := 0
	for {
		select {
		case <-myTimer.C:
			i++
			fmt.Println("count: ", i)
			SqlStmtTuning()
			myTimer.Reset(time.Second * 300)
		}
	}
}

func main1() {
	dbHost = flag.String("dbhost", "127.0.0.1", "the database address")
	Username = flag.String("userName", "000", "the user of the database address")
	dbPwd = flag.String("password", "0000", "the user password of the database address")
	database = flag.String("database", "test", "the default database ")
	DBPort = flag.Int("DBPort", 4000, "the port of the database")
	flag.Parse()
	initSqlLit()
	go StartBackgroudTunningJob()
	startWeb()
	//test()

}
func main() {
	i := 0
	for {
		if i > 2 {
			break
		}
		go stressTest6("select *  from gharchive_dev.github_events where state='SHH' and repo_name='sss'  and language='SS'")
		go stressTest6("select *  from gharchive_dev.github_events where state='SHH' and repo_name='sss'  and language='SS'")
		go stressTest6("select * from  gharchive_dev.github_events b ,gharchive_dev.github_events_bak a where  b.repo_name='repo_name' and  b.deletions=0 and a.actor_id=1231312 and a.commit_id=b.commit_id")
		go stressTest6("select * from  gharchive_dev.github_events b where  b.repo_name='repo_name' and  b.deletions=0")
		go stressTest6("select *  from gharchive_dev.github_events where state='SHH' and repo_name='sss'  and language='SS'")
		go stressTest6("select *  from gharchive_dev.github_events where state='SHH' and repo_name='sss'  and language='SS'")

		go stressTest6("select * from  gharchive_dev.github_events b ,gharchive_dev.github_events_bak a where  b.repo_name='repo_name' and  b.deletions=0 and a.actor_id=1231312 and a.commit_id=b.commit_id")

		go stressTest6("select count(*) from gharchive_dev.github_events")
		go stressTest6("select * from  gharchive_dev.github_events b ,gharchive_dev.github_events_bak a where  b.repo_name='repo_name' and  b.deletions=0 and a.actor_id=1231312 and a.commit_id=b.commit_id")
		i++
	}
	time.Sleep(time.Minute * 60)
}
func startWeb() {
	e := gin.Default() //创建一个默认的路由引擎
	advisorGroup := e.Group("/sqladvisor")
	advisorGroup.GET("/topSlowQuerySummary", GetTopSlowQuery)
	advisorGroup.GET("/SqlStmtsTuningResults", doingSqlStmtTuning)
	advisorGroup.GET("/QueryTunningResults", GetTunningResults)
	advisorGroup.GET("/GetTunningDetail", GetTunningResultDetail)
	advisorGroup.GET("/GetSlowQueriesByDigest", GetSlowQueriesByDigest)

	e.Run(":8080")
}

func stressTest6(sqlTxt string) {
	db, err := sql.Open("mysql", fmt.Sprintf("%s:%s@tcp(%s:%d)/%s?charset=utf8", "000", "123455", "127.0.0.1", 4000, "test"))
	defer db.Close()
	if err != nil {
		fmt.Errorf("open db failed. %s", err)
	}
	i := 0
	for i < 3000000000000 {
		rows, err := db.Query(sqlTxt)
		if err != nil {
			fmt.Println(err)
		}
		for rows.Next() {
			fmt.Println("ssssssssssss")
		}
		i++
	}
}

func test() {
	//sql2 := "select count(*) from test.customer where c_phone='12321323123' or C_ACCTBAL=234124124"
	//sql2 := "select count(*) from test.customer a, test.orders o where a.C_CUSTKEY=o.O_CUSTKEY and a.C_NAME='TOM' or a.C_MKTSEGMENT='b' and o.O_COMMENT='sss';"
	//sql2 := "select * from test.customer "
	//sql2 := "select min(o_comment) from orders;"
	sql2 := "select row_num, exe_time as exeTime, Query as queryText   ,queryTime,DIGEST, connection, UNIX_TIMESTAMP(timeAt) as timeAt ,db11,TidbInstance from ( select row_number() over( partition by DATE_FORMAT( Time,'%y-%m-%d %H:%i')  order by Query_time desc) as row_num, UNIX_TIMESTAMP(DATE_FORMAT(Time,'%Y-%m-%d %H:%i:00')) as exe_time,DIGEST ,Time as timeAt,Conn_ID as connection,Query, format(Query_time,4) as queryTime ,`DB` as db11,`INSTANCE` as  TidbInstance from INFORMATION_SCHEMA.cluster_slow_query where plan  like '%tiflash%' and Time>SUBDATE(now(),interval 3600 second) and `DB` in ('test') and query not like 'load%') ss where row_num<=10 order by  exe_time,queryTime desc"
	rs := strings.Split(sql2, "(")
	fmt.Println(rs)
	res := base64.StdEncoding.EncodeToString([]byte(sql2))
	var sqlParsedResult = make(map[string]*Table_Info)
	checkResults := tuningSqlStmt(sql2, "test", res, sqlParsedResult)
	poorSql := poor_sql{SqlTxt: sql2, Digest: res, ExecutionDB: "myDB", Advisors: checkResults}
	impact := 0
	for _, item := range checkResults {
		if item.Suggestion == "MISS_WHERE_CLAUSE_WITHOUT_AP_FUC" {
			impact = impact + 0
		} else if item.Suggestion == "MISS_WHERE_CLAUSE_WITH_AP_FUC" {
			impact = impact + 150
			break
		} else if item.Suggestion == "MISS_INDEX" {
			impact = impact + 300
			break
		}
	}
	poorSql.Impact = strconv.Itoa(impact) + "%"
	bts, err1 := json.Marshal(poorSql)
	if err1 == nil {
		fmt.Println(string(bts))
	}
	fmt.Println(time.Now().Unix())
	initSqlLit()
	SaveResultsToDB(poorSql)
	db, _ := sql.Open("sqlite3", "./foo11.db")
	rows, err := db.Query("select  Digest, advisors from TuningResult ")
	digest := ""
	advisors := ""
	if err == nil {
		for rows.Next() {
			rows.Scan(&digest, &advisors)
			fmt.Printf("In SQLLite: disgest is  %s, advisors : %s", digest, advisors)
		}
	}
	strs := QueryTuningResultsInOneHour()
	fmt.Printf("%v", strs)
	//fmt.Println(poorSql)
	//spew.Sdump(*astNode)
	//fmt.Printf((visitor.sqlDiges))
	//fmt.Printf("%v\n", spew.Sdump(*astNode))
}
