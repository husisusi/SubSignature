# SubSignature for HCL Domino - server agent 0.5.3

A LotusScript agent that writes the signatures maintained in **SubSignature** into the mail
files of your Domino servers - at night by schedule, or by hand.

* SubSignature (1.8.0 or newer) delivers every signature as **Notes rich text (DXL)** with the
  pictures embedded (`GET /api/v1/signatures/{id}?notes=dxl`). The agent checks it and imports it
  as the mail file's rich-text signature (`Signature_Rich` in the `CalendarProfile`) - stored
  exactly like a signature set up by hand in Notes.
* Only mail files on the servers listed in the configuration file, and only for people who
  **have a signature in SubSignature**.
* **Central** (one server does the work for all servers, setting `agent_server`) or
  **distributed** (every mail server handles its own mail files) - see below.
* A mail file is written **only when its signature changed** (data, template or company
  details). Before the first change the old signature is saved (backup).
* All settings are in a text file, **`subsignature-domino.ini`**, in the Domino data directory -
  no settings in the code.

Tested with Domino 14.0 FP5 (mail template mail14.ntf).

## Central or distributed

| | Central (`agent_server` set) | Distributed (`agent_server` empty) |
|---|---|---|
| Where the agent works | only on `agent_server` | on every server listed in `servers` |
| Which mail files | those of **all** servers in `servers`, over the network | only those of the server it runs on |
| Control database and `.ini` file | only on `agent_server` | on every listed server |
| Prerequisite | every server in `servers` (other than `agent_server`) lists `agent_server` under **Trusted servers** | none |
| If the agent server is down | no updates until it is back | the other servers keep working |

Example (central): the agent runs on `domino-hub` and writes the mail files on
`domino-mail1` and `domino-mail2`:

```
servers = domino-mail1/Example, domino-mail2/Example
agent_server = domino-hub/Example
```

Add `domino-hub/Example` to `servers` as well if its own mail files should also get
signatures.

**Trusted servers:** in the server document of `domino-mail1` and `domino-mail2`, tab
**Security**, field **Trusted servers**, add `domino-hub/Example`. The change is active once the
Domino Directory has replicated to that server; restart the server if it does not take effect. Without it, Domino does not let an agent on `domino-hub` open
databases there; the log then says `cannot open the mail file ... must list ... under 'Trusted
servers'`.

The status report uses the **mail server** as the device (`Domino domino-mail1`), so SubSignature
shows the same devices in both modes.

## Setup

### 1. Control database

The control database (e.g. `mail\subsigna.nsf`) holds the agents, the backups and the state
documents. **Central:** only on `agent_server`. **Distributed:** a **replica on every listed
server** (File -> Replication -> New Replica). ACL: `-Default-` and `Anonymous` **No Access**,
administrators and `LocalDomainServers` **Manager**.

### 2. Configuration file

Copy `subsignature-domino.ini` into the **Domino data directory** of the server(s) that run the
agent (e.g. `D:\HCL\Domino\Data\subsignature-domino.ini`) and fill in `url`, `token`, `servers`
and, for central mode, `agent_server`. In distributed mode the same file can be used on all
servers: `servers` decides where the agent acts. The file contains the API token - make sure only
Domino administrators can read it.

### 3. The agent "SubSignature"

In Domino Designer, open the existing agent **SubSignature** (or create a new LotusScript agent
with this name), click into the code, **Ctrl+A**, paste the whole `SubSignatureDomino.lss`,
**Ctrl+S**. Then in the agent properties:

* **Basics:** Trigger **On schedule**, **Daily**; Target **None**.
* **Schedule:** start time e.g. **02:00**. **Central:** **Run on:** `agent_server`.
  **Distributed:** **Run on: -Any Server-** (it then runs on every server that has a replica;
  each server only handles its own mail files).
* **Security:** runtime security level **2. Allow restricted operations**.
* Check that the Problems tab is empty and the agent is **enabled**.

### 4. Starting it by hand

* **From the Notes client:** open the control database **from the server that should run it**
  (central: `agent_server`) and start the helper agent **Run SubSignature on server** (Actions menu). It calls
  `RunOnServer` - the agent runs on that server, the output goes to the server console and
  `log.nsf`.
* **From the server console:** `tell amgr run "mail\subsigna.nsf" 'SubSignature'` (if the agent's
  name is in parentheses: `'(SubSignature)'`).

The helper agent is in `start-agent.lss` (trigger **Action menu selection**, target **None**):
create a LotusScript agent named e.g. **Run SubSignature on server**, paste the file, save. If your
main agent has a different name, change `TARGET_AGENT` at the top. The code:

```
' SubSignature for HCL Domino - helper agent "Run SubSignature on server".
' Trigger: Action menu selection, target: None. Starts the agent TARGET_AGENT
' with RunOnServer on the server that holds this database.
Sub Initialize
	Const TARGET_AGENT = "SubSignature"
	Dim s As New NotesSession
	Dim db As NotesDatabase
	Dim ag As NotesAgent
	Dim names As String
	Dim rc As Integer

	Set db = s.CurrentDatabase
	' Hidden agents (Agent list selection) may need the name in parentheses.
	Set ag = db.GetAgent(TARGET_AGENT)
	If ag Is Nothing Then Set ag = db.GetAgent("(" & TARGET_AGENT & ")")
	If ag Is Nothing Then
		' List all agents so the right name can be copied into TARGET_AGENT.
		ForAll a In db.Agents
			names = names & Chr$(10) & a.Name
		End ForAll
		Messagebox "Agent '" & TARGET_AGENT & "' not found. Agents in this database:" & names, 16, "RunOnServer"
		Exit Sub
	End If

	' Runs the agent on the server that holds this database and waits for it.
	rc = ag.RunOnServer()
	If rc = 0 Then
		Messagebox "Finished on the server - see the server console or log.nsf.", 64, "RunOnServer"
	Else
		Messagebox "RunOnServer returned " & rc & " - see the server console.", 16, "RunOnServer"
	End If
End Sub```

### 5. Rights

* The agent signer needs **"Sign or run restricted LotusScript/Java agents"** in the server
  document of every server the agent runs on.
* The agent needs **Editor access** (or higher) to the mail files - in central mode also to those
  on the other servers. SHOW lists the access per mail file. If the signer is not in the mail
  files' ACLs, set **Run on behalf of** (Security tab) to the name of the server running the
  agent: servers are normally Manager in mail files via `LocalDomainServers`. The signer then
  needs "Sign agents to run on behalf of someone else".
* Central mode: **Trusted servers** on the other servers (see above).
* Scheduled agents are stopped by the Agent Manager after its maximum run time (server document
  -> Server Tasks -> Agent Manager). `max_minutes` makes the agent stop on its own before that and
  continue in the next run.

## Recommended first steps

| Step | `mode` | `test_address` | `limit` | Check |
|---|---|---|---|---|
| 1 | `SHOW` | one test mail file | - | the log: signature found, security check passed, "would write" |
| 2 | `APPLY` | the same | - | Notes: new mail, reply, mail to an external address |
| 3 | `SHOW` | empty | `10` | which mail files would be written, access rights |
| 4 | `APPLY` | empty | `10` | the first 10 mail files |
| 5 | `APPLY` | empty | `0` | everyone - from now on every night |

`test_address` always lets you test one mail file, also later in production. Note that the
schedule uses the same file: what you set there also applies to the next night.

## Settings (`subsignature-domino.ini`)

| Setting | Default | Meaning |
|---|---|---|
| `url` | - | https address of the SubSignature server |
| `token` | - | API token with *Read signatures* (+ *Report sync status*) |
| `servers` | - | servers whose mail files get the signatures, comma-separated. Common name (`domino-hub`), abbreviated (`domino-hub/Example`) or canonical name; organizational units may be left out. Unknown names are reported in the log together with the mail servers found in the directory. |
| `agent_server` | empty | central mode: the one server that does the work for all `servers`; empty = every listed server handles its own mail files |
| `mode` | `SHOW` | `SHOW` (dry run, changes nothing), `APPLY`, `RESTORE`, `EXPORT_DXL` |
| `test_address` | empty | only the mail file of this Internet address; empty = all |
| `limit` | `10` | at most this many signatures per run - the first ones found, in the order of the SubSignature IDs; `0` = no limit |
| `on_deleted` | `keep` | when a signature written by the agent is deleted in SubSignature: `keep` (stays in Notes), `restore` (signature from before SubSignature), `remove` (removed and switched off) |
| `report_status` | `true` | report the result to SubSignature (All Signatures shows the device `Domino <server>`) |
| `force_update` | `false` | `true` writes all signatures again, even unchanged ones |
| `max_minutes` | `30` | stop after this many minutes, continue in the next run; `0` = no own limit |
| `directory` | `names.nsf` | Domino Directory on this server |

`RESTORE` and `EXPORT_DXL` only work with `test_address` (one mail file).

## What a run does

1. Reads `subsignature-domino.ini`; stops if this server is not `agent_server` (central) or not
   in `servers` (distributed).
2. Reads the **Person documents** from the Domino Directory (Internet address -> mail file and
   `MailServer`): central - all listed servers; distributed - this server.
3. Reads the **signature list** from SubSignature and keeps the signatures whose address has a
   mail file on one of these servers (several signatures for one address: the newest).
4. For each of them (up to `limit`, up to `max_minutes`):
   * **unchanged** since the last write -> nothing to do;
   * otherwise fetches the Notes version, **checks** it (only text, fonts, links, pictures and
     tables; links only http/https/mailto/tel; length as announced by the server), imports it
     into a temporary document, saves the **backup** (first time only) and writes it;
   * if SubSignature could not load a picture yet, the mail file is left unchanged and tried
     again in the next run.
5. **Deleted signatures** (`on_deleted`) - only in a run over all mail files that was not cut
   short by `limit` or `max_minutes`.
6. Sends the **status report** to SubSignature and writes a summary to the log.

## Documents in the control database

| Form | One per | Content |
|---|---|---|
| `SubSigBackup` | mail file | the signature items from **before SubSignature** (`SSB_Address`, `SSB_MailFile`, `SSB_MailServer`, `SSB_Created`, `SSB_Items`); kept until `RESTORE` / `on_deleted = restore` |
| `SubSigState` | mail file | what was written last (`SSS_Address`, `SSS_MailFile`, `SSS_Server` = server of the mail file, `SSS_SignatureId`, `SSS_HtmlSha`, `SSS_Written`) |

To look at them, create two views in Designer, e.g. selection `SELECT Form = "SubSigBackup"`
and `SELECT Form = "SubSigState"`, with the address and date fields as columns. Deleting a
state document makes the agent write that mail file again in the next run. Backups and state
documents use the mail file's server in their key, so switching between central and distributed
mode keeps them valid. When you switch
to central mode, copy existing `SubSigBackup` / `SubSigState` documents to the control database
on `agent_server` (they are already there if it is a replica).

## All Signatures in SubSignature

With `report_status = true` every run reports each mail file it looked at. Because the agent
runs once a night, set **Admin -> Configuration -> Agent sync freshness window** to about
**26 hours**, so the badges do not turn yellow during the day.

## Troubleshooting

| Message | Cause / fix |
|---------|-------------|
| `CONFIG: ... not found` | `subsignature-domino.ini` is missing in the data directory of this server. |
| `This server is not listed under 'servers'` | Distributed mode: intended, add the server to `servers` if it should act. |
| `agent_server is ... - only that server works` | Central mode: intended on all other servers. |
| `cannot open the mail file ... must list ... under 'Trusted servers'` | Central mode: add `agent_server` to the **Trusted servers** field of that server's document; check the connection between the servers. |
| `The mail file of ... is not on this server` / `... not on one of the servers listed` | The line above it says why: `... has the mail file ... on <server> - that server is not in 'servers'` (add it), or `no Person document ... has the Internet address ...` (check the field InternetAddress of the Person document). |
| `WARNING: no person has a mail file on the server '...'` | The name in `servers` matches no mail server of the directory - the log lists the names it found. |
| `has only Reader access ... (Editor or higher is needed)` | ACL of the mail file, or use *Run on behalf of* the server. |
| `the mail preferences ... were never saved` | The mail file has no `CalendarProfile` yet; the owner opens the mail preferences once and saves them. |
| `picture missing (not_allowed)` | Host missing under SubSignature Configuration -> Image hosts for embedding. |
| `a picture could not be loaded by the SubSignature server yet` | Remote pictures are fetched step by step; the next run continues. |
| `the answer has no Notes version` / `(unavailable)` | SubSignature older than 1.8.0 with `notes=dxl`, or PHP `dom` missing on the SubSignature server. |
| `refused - the rich text contains the element <...>` | The DXL contains something other than text, fonts, links, pictures and tables - nothing is imported. |
| `Limit reached` / `Time limit reached` | Intended; raise `limit` / `max_minutes`, or wait for the next run. |
| `Deleted signatures: not checked in this run` | Only complete runs (no `test_address`, not cut short) handle deleted signatures. |
| `JSON: the response could not be parsed (4240)` | Agent 0.5.2 or older: the signature list of a run without `test_address` is larger than 64 KB. Fixed in 0.5.3 - every API answer is now read with `PreferJSONNavigator`, which has no size limit. |
| `HTTP 200, but the answer is not JSON` | Something between Domino and SubSignature (proxy, login page) answers instead of the API - check `url`. |
| `error 4179 ... restricted operation` | Security level 2, and the signer's right to run restricted agents on this server. |
| TLS / certificate errors | Domino 14.0.x uses `cacerts.pem` in the data directory (ISRG Root X1 for Let's Encrypt); 14.5+ the trusted roots in the Domino Directory. |
| `HTTP 401` / `HTTP 403` | Token wrong, expired or revoked / missing permission. |
| Signature not visible in Notes | The user has to close and reopen the mail file (Notes caches the profile); local replicas after replication. |
