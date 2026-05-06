package db

import (
	"errors"
	"fmt"
	"strconv"
	"encoding/base64"

	"Havoc/pkg/agent"
)

func (db *DB) AgentAdd(agent *agent.Agent) error {

	var err error
	var AgentID int64

	AgentID, err = strconv.ParseInt(agent.NameID, 16, 32)
	if err != nil {
		return err
	}

	/* check if it's a new db */
	if db.Existed() {

		/* check if agent already exists */
		if db.AgentExist(int(AgentID)) {
			return nil
		}

	} else {

		/* check if agent already exists */
		if db.AgentExist(int(AgentID)) {
			return errors.New(fmt.Sprintf("agent %x already exist in db", agent.NameID))
		}

	}

	/* prepare some arguments to execute for the sqlite db */
	stmt, err := db.db.Prepare("INSERT INTO TS_Agents ( AgentID, Active, Reason, AESKey, AESIv, Hostname, Username, DomainName, ExternalIP, InternalIP, ProcessName, BaseAddress, ProcessPID, ProcessTID, ProcessPPID, ProcessArch, Elevated, OSVersion, OSArch, SleepDelay, SleepJitter, KillDate, WorkingHours, FirstCallIn, LastCallIn, Notes) values(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)")
	if err != nil {
		return err
	}

	/* add the data to the agent table */
	_, err = stmt.Exec(
		int(AgentID),
		1,
		"",
		base64.StdEncoding.EncodeToString(agent.Encryption.AESKey),
		base64.StdEncoding.EncodeToString(agent.Encryption.AESIv),
		agent.Info.Hostname,
		agent.Info.Username,
		agent.Info.DomainName,
		agent.Info.ExternalIP,
		agent.Info.InternalIP,
		agent.Info.ProcessName,
		agent.Info.BaseAddress,
		agent.Info.ProcessPID,
		agent.Info.ProcessTID,
		agent.Info.ProcessPPID,
		agent.Info.ProcessArch,
		agent.Info.Elevated,
		agent.Info.OSVersion,
		agent.Info.OSArch,
		agent.Info.SleepDelay,
		agent.Info.SleepJitter,
		agent.Info.KillDate,
		agent.Info.WorkingHours,
		agent.Info.FirstCallIn,
		agent.Info.LastCallIn,
		agent.Notes)
	if err != nil {
		return err
	}

	stmt.Close()

	return nil
}

func (db *DB) AgentUpdate(agent *agent.Agent) error {

	var err error
	var AgentID int64
	var active int

	AgentID, err = strconv.ParseInt(agent.NameID, 16, 32)
	if err != nil {
		return err
	}

	/* check if agent already exists */
	if db.AgentExist(int(AgentID)) == false {
		return errors.New("Agent does not exist")
	}

	/* prepare some arguments to execute for the sqlite db */
	stmt, err := db.db.Prepare("UPDATE TS_Agents SET Active = ?, Reason = ?, AESKey = ?, AESIv = ?, Hostname = ?, Username = ?, DomainName = ?, ExternalIP = ?, InternalIP = ?, ProcessName = ?, BaseAddress = ?, ProcessPID = ?, ProcessTID = ?, ProcessPPID = ?, ProcessArch = ?, Elevated = ?, OSVersion = ?, OSArch = ?, SleepDelay = ?, SleepJitter = ?, KillDate = ?, WorkingHours = ?, FirstCallIn = ?, LastCallIn = ? WHERE AgentID = ?")
	if err != nil {
		return err
	}

	if agent.Active {
		active = 1
	} else {
		active = 0
	}

	/* add the data to the agent table */
	_, err = stmt.Exec(
		active,
		agent.Reason,
		base64.StdEncoding.EncodeToString(agent.Encryption.AESKey),
		base64.StdEncoding.EncodeToString(agent.Encryption.AESIv),
		agent.Info.Hostname,
		agent.Info.Username,
		agent.Info.DomainName,
		agent.Info.ExternalIP,
		agent.Info.InternalIP,
		agent.Info.ProcessName,
		agent.Info.BaseAddress,
		agent.Info.ProcessPID,
		agent.Info.ProcessTID,
		agent.Info.ProcessPPID,
		agent.Info.ProcessArch,
		agent.Info.Elevated,
		agent.Info.OSVersion,
		agent.Info.OSArch,
		agent.Info.SleepDelay,
		agent.Info.SleepJitter,
		agent.Info.KillDate,
		agent.Info.WorkingHours,
		agent.Info.FirstCallIn,
		agent.Info.LastCallIn,
		int(AgentID))
	if err != nil {
		return err
	}

	stmt.Close()

	return nil
}

func (db *DB) AgentHasDied(AgentID int) bool {
	// prepare some arguments to execute for the sqlite db
	stmt, err := db.db.Prepare("UPDATE TS_Agents SET Active = 0 WHERE AgentID = ?")
	if err != nil {
		return false
	}

	// execute statement
	_, err = stmt.Exec(AgentID)
	stmt.Close()

	if err != nil {
		return false
	}

	return true
}

func (db *DB) AgentExist(AgentID int) bool {
	// prepare some arguments to execute for the sqlite db
	stmt, err := db.db.Prepare("SELECT COUNT(*) FROM TS_Agents WHERE AgentID = ?")
	if err != nil {
		return false
	}

	// execute statement
	query, err := stmt.Query(AgentID)
	defer query.Close()
	if err != nil {
		return false
	}

	for query.Next() {
		var NumRows int

		query.Scan(&NumRows)

		if NumRows == 1 {
			return true
		} else {
			return false
		}
	}

	return false
}

func (db *DB) AgentRemove(AgentID int) error {
	// prepare some arguments to execute for the sqlite db
	stmt, err := db.db.Prepare("DELETE FROM TS_Agents WHERE AgentID = ?")
	if err != nil {
		return err
	}

	// execute statement
	_, err = stmt.Exec(AgentID)
	stmt.Close()

	if err != nil {
		return err
	}

	return nil
}


func (db *DB) AgentSetNotes(AgentID int, notes string) error {
	stmt, err := db.db.Prepare("UPDATE TS_Agents SET Notes = ? WHERE AgentID = ?")
	if err != nil {
		return err
	}
	_, err = stmt.Exec(notes, AgentID)
	stmt.Close()
	return err
}

func (db *DB) AgentGetNotes(AgentID int) (string, error) {
	var notes string
	row := db.db.QueryRow("SELECT COALESCE(Notes,'') FROM TS_Agents WHERE AgentID = ?", AgentID)
	err := row.Scan(&notes)
	return notes, err
}

func (db *DB) AgentAddHistory(AgentID int, timeStr, cmdLine, output string) error {
	stmt, err := db.db.Prepare("INSERT INTO TS_AgentHistory (AgentID, Time, CommandLine, Output) VALUES (?, ?, ?, ?)")
	if err != nil {
		return err
	}
	_, err = stmt.Exec(AgentID, timeStr, cmdLine, output)
	stmt.Close()
	return err
}

// HistoryEntry represents a single console history row for an agent.
type HistoryEntry struct {
	ID          int64
	Time        string
	CommandLine string
	Output      string // full JSON string (what MessageOutput expects, not base64)
}

// AgentGetHistory returns all console history for the given AgentID ordered by insertion.
func (db *DB) AgentGetHistory(AgentID int) ([]HistoryEntry, error) {
	rows, err := db.db.Query(
		"SELECT ID, Time, CommandLine, Output FROM TS_AgentHistory WHERE AgentID = ? ORDER BY ID ASC",
		AgentID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var entries []HistoryEntry
	for rows.Next() {
		var e HistoryEntry
		if err := rows.Scan(&e.ID, &e.Time, &e.CommandLine, &e.Output); err != nil {
			return entries, err
		}
		entries = append(entries, e)
	}
	return entries, rows.Err()
}

func (db *DB) AgentAll() []*agent.Agent {

	var Agents []*agent.Agent

	query, err := db.db.Query("SELECT AgentID, Active, Reason, AESKey, AESIv, Hostname, Username, DomainName, ExternalIP, InternalIP, ProcessName, BaseAddress, ProcessPID, ProcessTID, ProcessPPID, ProcessArch, Elevated, OSVersion, OSArch, SleepDelay, SleepJitter, KillDate, WorkingHours, FirstCallIn, LastCallIn, COALESCE(Notes,'') FROM TS_Agents WHERE Active = 1")
	if err != nil {
		return nil
	}
	defer query.Close()

	for query.Next() {

		var (
			AgentID int
			Active int
			Reason string
			AESKey string
			AESIv string
			Hostname string
			Username string
			DomainName string
			ExternalIP string
			InternalIP string
			ProcessName string
			BaseAddress int64
			ProcessPID int
			ProcessTID int
			ProcessPPID int
			ProcessArch string
			Elevated string
			OSVersion string
			OSArch string
			SleepDelay int
			SleepJitter int
			KillDate int64
			WorkingHours int32
			FirstCallIn string
			LastCallIn string
			Notes string
		)

		/* read the selected items */
		err = query.Scan(&AgentID, &Active, &Reason, &AESKey, &AESIv, &Hostname, &Username, &DomainName, &ExternalIP, &InternalIP, &ProcessName, &BaseAddress, &ProcessPID, &ProcessTID, &ProcessPPID, &ProcessArch, &Elevated, &OSVersion, &OSArch, &SleepDelay, &SleepJitter, &KillDate, &WorkingHours, &FirstCallIn, &LastCallIn, &Notes)
		if err != nil {
			/* at this point we failed
			 * just return the collected agents */
			return Agents
		}

		BytesAESKey, _ := base64.StdEncoding.DecodeString(AESKey)
		BytesAESIv,  _ := base64.StdEncoding.DecodeString(AESIv)

		var Agent = &agent.Agent{
			Encryption: struct {
				AESKey []byte
				AESIv  []byte
			}{
				AESKey: BytesAESKey,
				AESIv:  BytesAESIv,
			},

			Active:     Active == 1,
			Reason:     Reason,
			SessionDir: "",

			Info: new(agent.AgentInfo),
		}

		Agent.NameID            = fmt.Sprintf("%08x", AgentID)
		Agent.SessionDir        = ""
		Agent.BackgroundCheck   = false
		Agent.TaskedOnce        = true
		Agent.Info.MagicValue   = agent.DEMON_MAGIC_VALUE
		Agent.Info.Listener     = nil
		Agent.Info.Hostname     = Hostname
		Agent.Info.Username     = Username
		Agent.Info.DomainName   = DomainName
		Agent.Info.ExternalIP   = ExternalIP
		Agent.Info.InternalIP   = InternalIP
		Agent.Info.ProcessName  = ProcessName
		Agent.Info.BaseAddress  = BaseAddress
		Agent.Info.ProcessPID   = ProcessPID
		Agent.Info.ProcessTID   = ProcessTID
		Agent.Info.ProcessPPID  = ProcessPPID
		Agent.Info.ProcessArch  = ProcessArch
		Agent.Info.Elevated     = Elevated
		Agent.Info.OSVersion    = OSVersion
		Agent.Info.OSArch       = OSArch
		Agent.Info.SleepDelay   = SleepDelay
		Agent.Info.SleepJitter  = SleepJitter
		Agent.Info.KillDate     = KillDate
		Agent.Info.WorkingHours = WorkingHours
		Agent.Info.FirstCallIn  = FirstCallIn
		Agent.Info.LastCallIn   = LastCallIn
		Agent.Notes             = Notes

		/* append collected agent to agent array */
		Agents = append(Agents, Agent)

	}

	return Agents
}
