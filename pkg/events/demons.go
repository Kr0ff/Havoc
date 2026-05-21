package events

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	"Havoc/pkg/agent"
	"Havoc/pkg/db"
	"Havoc/pkg/logr"
	"Havoc/pkg/packager"
)

/* TODO: rename everything here from 'Demon' to 'Agent' */

var Demons demons

func (demons) NewDemon(Agent *agent.Agent) packager.Package {
	var (
		Package    packager.Package
	)

	Package.Head.Event   = packager.Type.Session.Type
	Package.Head.Time    = time.Now().Format("02/01/2006 15:04:05")
	Package.Head.OneTime = "true"

	Package.Body.SubEvent = packager.Type.Session.NewSession
	Package.Body.Info = make(map[string]interface{})

	InfoMap := map[string]interface{}{
		"Active": fmt.Sprintf("%v", Agent.Active),
		"BackgroundCheck": Agent.BackgroundCheck,
		"DomainName": Agent.Info.DomainName,
		"Elevated": Agent.Info.Elevated,
		"Encryption": map[string]interface{}{
			"AESKey": base64.StdEncoding.EncodeToString(Agent.Encryption.AESKey),
			"AESIv":  base64.StdEncoding.EncodeToString(Agent.Encryption.AESIv),
		},
		"InternalIP": Agent.Info.InternalIP,
		"ExternalIP": Agent.Info.ExternalIP,
		"FirstCallIn": Agent.Info.FirstCallIn,
		"LastCallIn": Agent.Info.LastCallIn,
		"Hostname": Agent.Info.Hostname,
		"Listener": func() string {
			if Agent.Info.Listener != nil {
				if name, ok := Agent.Info.Listener.(string); ok {
					return name
				}
			}
			return "unknown"
		}(),
		"MagicValue": fmt.Sprintf("%x", Agent.Info.MagicValue),
		"NameID": Agent.NameID,
		"OSArch": Agent.Info.OSArch,
		"OSBuild": Agent.Info.OSBuild,
		"OSVersion": Agent.Info.OSVersion,
		"Pivots": map[string]interface{}{
			"Parent": nil,
			"Links":  []string{},
		},
		"PortFwds": []string{},
		"ProcessArch": Agent.Info.ProcessArch,
		"ProcessName": Agent.Info.ProcessName,
		"ProcessPID": fmt.Sprintf("%d", Agent.Info.ProcessPID),
		"ProcessPPID": fmt.Sprintf("%d", Agent.Info.ProcessPPID),
		"ProcessPath": Agent.Info.ProcessPath,
		"Reason": Agent.Reason,
		"SleepDelay": Agent.Info.SleepDelay,
		"SleepJitter": Agent.Info.SleepJitter,
		"KillDate": Agent.Info.KillDate,
		"WorkingHours": Agent.Info.WorkingHours,
		"SocksCli": []string{},
		"SocksCliMtx": nil,
		"SocksSvr": []string{},
		"TaskedOnce": Agent.TaskedOnce,
		"Username": Agent.Info.Username,
		"PivotParent": "",
		"Notes": Agent.Notes,
	}

	if Agent.Pivots.Parent != nil {
		InfoMap["PivotParent"] = Agent.Pivots.Parent.NameID
	}

	Package.Body.Info = InfoMap

	return Package
}

func (demons) DemonOutput(DemonID string, CommandID int, Output string) packager.Package {
	var Package packager.Package
	var LogrOut map[string]string

	err := json.Unmarshal([]byte(Output), &LogrOut)
	if err == nil && CommandID != agent.COMMAND_NOJOB {
		logr.LogrInstance.DemonAddOutput(DemonID, LogrOut, time.Now().UTC().Format("02/01/2006 15:04:05"))
	}

	Package.Head.Event = packager.Type.Session.Type
	Package.Head.Time = time.Now().Format("02/01/2006 15:04:05")

	Package.Body.SubEvent = packager.Type.Session.Output
	Package.Body.Info = make(map[string]interface{})

	Package.Body.Info["DemonID"] = DemonID
	Package.Body.Info["CommandID"] = strconv.Itoa(CommandID)
	Package.Body.Info["Output"] = base64.StdEncoding.EncodeToString([]byte(Output))

	return Package
}

func (demons) CallBack(DemonID string, callback string) packager.Package {
	var Package packager.Package

	Package.Head.Event = packager.Type.Session.Type
	Package.Head.Time = time.Now().Format("02/01/2006 15:04:05")

	Package.Body.SubEvent = packager.Type.Session.Output
	Package.Body.Info = make(map[string]interface{})

	Package.Body.Info["DemonID"] = DemonID
	Package.Body.Info["CommandID"] = "10"
	Package.Body.Info["Output"] = callback

	return Package
}

func (demons) MarkAs(AgentID, Mark string) packager.Package {
	var Package packager.Package

	Package.Head.Event = packager.Type.Session.Type
	Package.Head.Time = time.Now().Format("02/01/2006 15:04:05")

	Package.Body.SubEvent = packager.Type.Session.MarkAsDead
	Package.Body.Info = make(map[string]interface{})

	Package.Body.Info["AgentID"] = AgentID
	Package.Body.Info["Marked"] = Mark

	return Package
}

// DemonHistory builds a Session.History event containing all console history
// entries for a given agent. This event is sent only to the newly connecting
// client (OneTime="true") immediately after the NewDemon event.
func (demons) DemonHistory(agentID string, entries []db.HistoryEntry) packager.Package {
	var Package packager.Package

	Package.Head.Event   = packager.Type.Session.Type
	Package.Head.Time    = time.Now().Format("02/01/2006 15:04:05")
	Package.Head.OneTime = "true"

	Package.Body.SubEvent = packager.Type.Session.History
	Package.Body.Info = make(map[string]interface{})
	Package.Body.Info["DemonID"] = agentID

	type jsonEntry struct {
		Time        string `json:"Time"`
		CommandLine string `json:"CommandLine"`
		Output      string `json:"Output"` // base64 of the full JSON string
	}

	var jsonEntries []jsonEntry
	for _, e := range entries {
		je := jsonEntry{
			Time:        e.Time,
			CommandLine: e.CommandLine,
		}
		if e.Output != "" {
			je.Output = base64.StdEncoding.EncodeToString([]byte(e.Output))
		}
		jsonEntries = append(jsonEntries, je)
	}

	entriesJSON, _ := json.Marshal(jsonEntries)
	Package.Body.Info["Entries"] = base64.StdEncoding.EncodeToString(entriesJSON)

	return Package
}
