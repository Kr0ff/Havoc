package db

import (
	"database/sql"
	"os"

	_ "github.com/mattn/go-sqlite3"
)

type DB struct {
	existed bool
	db      *sql.DB
	path    string
}

func DatabaseNew(dbpath string) (*DB, error) {
	var (
		db  = new(DB)
		err error
	)

	db.path = dbpath

	db.existed = true
	if _, err = os.Stat(dbpath); os.IsNotExist(err) {
		db.existed = false
	}

	/* creates and or opens a db */
	db.db, err = sql.Open("sqlite3", db.path)
	if err != nil {
		return nil, err
	}

	if !db.existed {

		/* create db tables */
		err = db.init()
		if err != nil {
			return nil, err
		}

	} else {

		/* apply schema migrations for older databases */
		err = db.migrate()
		if err != nil {
			return nil, err
		}

	}

	return db, nil
}

func (db *DB) init() error {
	var err error

	_, err = db.db.Exec(`CREATE TABLE "TS_Listeners" ("Name" text UNIQUE, "Protocol" text, "Config" text);`)
	if err != nil {
		return err
	}

	_, err = db.db.Exec(`CREATE TABLE "TS_Agents" ("AgentID" int, "Active" int, "Reason" string, "AESKey" string, "AESIv" string, "Hostname" string, "Username" string, "DomainName" string, "ExternalIP" string, "InternalIP" string, "ProcessName" string, BaseAddress int, "ProcessPID" int, "ProcessTID" int, "ProcessPPID" int, "ProcessArch" string, "Elevated" string, "OSVersion" string, "OSArch" string, "SleepDelay" int, "SleepJitter" int, "KillDate" int, "WorkingHours" int, "FirstCallIn" string, "LastCallIn" string, "Notes" text DEFAULT '');`)
	if err != nil {
		return err
	}

	_, err = db.db.Exec(`CREATE TABLE "TS_Links" ("ParentAgentID" int, "LinkAgentID" int);`)
	if err != nil {
		return err
	}

	_, err = db.db.Exec(`CREATE TABLE "TS_AgentHistory" ("ID" INTEGER PRIMARY KEY AUTOINCREMENT, "AgentID" int, "Time" text, "CommandLine" text, "Output" text);`)
	if err != nil {
		return err
	}

	return nil
}

// migrate adds new columns and tables to an existing database that was created
// before Notes and history support was introduced.
func (db *DB) migrate() error {
	// Add Notes column to TS_Agents if it is missing.
	_, _ = db.db.Exec(`ALTER TABLE TS_Agents ADD COLUMN "Notes" text DEFAULT ''`)

	// Create TS_AgentHistory table if it does not exist yet.
	_, err := db.db.Exec(`CREATE TABLE IF NOT EXISTS "TS_AgentHistory" ("ID" INTEGER PRIMARY KEY AUTOINCREMENT, "AgentID" int, "Time" text, "CommandLine" text, "Output" text);`)
	return err
}

func (db *DB) Existed() bool {
	return db.existed
}

func (db *DB) Path() string {
	return db.path
}
