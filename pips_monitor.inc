/* PIPS Scanner monitoring: SQLite persistence and background ICMP sampling.
   All SQLite access happens on the UI thread. Worker threads only post results. */
#define PIPS_MAX_MON 1024
#define PIPS_MAX_SUBNETS 64
#define PIPS_MAX_INFLIGHT 8
typedef struct {
    RES res;
    WCHAR subnet[32];
    int interval, failures, successes, pending;
    DWORD next_tick;
    sqlite3_int64 last_ts;
} PipsMon;
typedef struct { int index; DWORD ip; int ok, rtt; } PipsMonResult;
static PipsMon g_mon[PIPS_MAX_MON];
static int g_nmon, g_mon_inflight, g_mon_mode, g_mon_subnet = -1;
static int g_mon_batch;
static int g_scanner_expanded = 1, g_monitor_expanded = 1;
static WCHAR g_mon_subnets[PIPS_MAX_SUBNETS][32];
static int g_nsubnets;
static sqlite3 *g_db;
static WCHAR g_datadir[MAX_PATH], g_dbpath[MAX_PATH];

static void refill(void);
static void invalidate_tabs(void);
static void status_dirty(void);
static int ini_read(const WCHAR *sec,const WCHAR *key,WCHAR *out,int cap);

static void pips_db_exec(const char *sql) {
    if (g_db) sqlite3_exec(g_db, sql, NULL, NULL, NULL);
}
static void pips_data_init(void) {
    WCHAR exe[MAX_PATH]; DWORD n = GetModuleFileNameW(NULL, exe, MAX_PATH);
    while (n && exe[n-1] != '\\') n--;
    exe[n] = 0;
    WCHAR marker[MAX_PATH]; wsprintfW(marker, L"%sportable.flag", exe);
    if (GetFileAttributesW(marker) != INVALID_FILE_ATTRIBUTES) {
        wsprintfW(g_datadir, L"%sData", exe);
    } else {
        DWORD len = GetEnvironmentVariableW(L"LOCALAPPDATA", g_datadir, MAX_PATH - 32);
        if (!len || len >= MAX_PATH - 32) return;
        lstrcatW(g_datadir, L"\\PIPS Scanner");
    }
    CreateDirectoryW(g_datadir, NULL);
    wsprintfW(g_dbpath, L"%s\\pips.db", g_datadir);
    if (sqlite3_open16(g_dbpath, &g_db) != SQLITE_OK) {
        if (g_db) { sqlite3_close(g_db); g_db = NULL; }
        return;
    }
    sqlite3_busy_timeout(g_db, 3000);
    pips_db_exec("PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL; PRAGMA foreign_keys=ON;");
    pips_db_exec("CREATE TABLE IF NOT EXISTS devices("
        "ip TEXT PRIMARY KEY, mac TEXT, name TEXT, vendor TEXT, type TEXT, comment TEXT, last_seen INTEGER);");
    pips_db_exec("CREATE TABLE IF NOT EXISTS monitoring("
        "ip TEXT PRIMARY KEY, subnet TEXT NOT NULL, interval_sec INTEGER NOT NULL,"
        "alive INTEGER NOT NULL DEFAULT 0, last_ping INTEGER DEFAULT 0, last_rtt INTEGER DEFAULT -1);");
    pips_db_exec("CREATE TABLE IF NOT EXISTS ping_history("
        "id INTEGER PRIMARY KEY, ip TEXT NOT NULL, ts INTEGER NOT NULL, rtt INTEGER, ok INTEGER NOT NULL);");
    pips_db_exec("CREATE INDEX IF NOT EXISTS ping_history_time ON ping_history(ts);");
    pips_db_exec("CREATE INDEX IF NOT EXISTS ping_history_ip_time ON ping_history(ip, ts);");
    pips_db_exec("CREATE TABLE IF NOT EXISTS events("
        "id INTEGER PRIMARY KEY, ip TEXT NOT NULL, ts INTEGER NOT NULL, event TEXT NOT NULL);");
    pips_db_exec("CREATE TABLE IF NOT EXISTS app_settings(key TEXT PRIMARY KEY, value TEXT);");
}
static void pips_sql_text(sqlite3_stmt *st, int col, const WCHAR *value) {
    sqlite3_bind_text16(st, col, value, -1, SQLITE_TRANSIENT);
}
static void pips_subnet_refresh(void) {
    g_nsubnets = 0;
    for (int i = 0; i < g_nmon; i++) {
        int found = 0;
        for (int j = 0; j < g_nsubnets; j++) if (!lstrcmpW(g_mon_subnets[j], g_mon[i].subnet)) found = 1;
        if (!found && g_nsubnets < PIPS_MAX_SUBNETS)
            lstrcpynW(g_mon_subnets[g_nsubnets++], g_mon[i].subnet, 32);
    }
    if (g_mon_subnet >= g_nsubnets) g_mon_subnet = -1;
}
static void pips_default_subnet(DWORD ip, WCHAR *out) {
    WCHAR net[16];
    DWORD mask = 0xFFFFFF00u;
    if (g_edit) {
        WCHAR input[512]; GetWindowTextW(g_edit,input,512);
        WCHAR *cursor=input,*token;
        while((token=next_tok(&cursor))!=NULL) {
            WCHAR *slash=wchr(token,L'/');if(!slash)continue;
            *slash++=0;
            DWORD base=0;if(!parse_ip(token,&base))continue;
            int bits=_wtoi(slash);if(bits<0||bits>32)continue;
            DWORD candidate=bits?0xFFFFFFFFu<<(32-bits):0;
            if((ip&candidate)==(base&candidate)) {
                ip2w(base&candidate,net);wsprintfW(out,L"%s/%d",net,bits);return;
            }
        }
    }
    ip2w(ip & mask, net);
    wsprintfW(out, L"%s/24", net);
}
static void pips_monitor_store(PipsMon *m) {
    if (!g_db) return;
    sqlite3_stmt *st = NULL;
    const char *q = "INSERT INTO monitoring(ip,subnet,interval_sec,alive,last_ping,last_rtt) "
       "VALUES(?,?,?,?,?,?) ON CONFLICT(ip) DO UPDATE SET subnet=excluded.subnet,"
       "interval_sec=excluded.interval_sec,alive=excluded.alive,last_ping=excluded.last_ping,last_rtt=excluded.last_rtt";
    if (sqlite3_prepare_v2(g_db, q, -1, &st, NULL) == SQLITE_OK) {
        pips_sql_text(st, 1, m->res.ips); pips_sql_text(st, 2, m->subnet);
        sqlite3_bind_int(st, 3, m->interval); sqlite3_bind_int(st, 4, m->res.alive);
        sqlite3_bind_int64(st, 5, m->last_ts); sqlite3_bind_int(st, 6, m->res.rtt);
        sqlite3_step(st);
    }
    sqlite3_finalize(st);
}
static void pips_device_store(RES *r) {
    if (!g_db || !r->alive) return;
    sqlite3_stmt *st = NULL;
    const char *q = "INSERT INTO devices(ip,mac,name,vendor,type,comment,last_seen) VALUES(?,?,?,?,?,?,?) "
        "ON CONFLICT(ip) DO UPDATE SET mac=excluded.mac,name=CASE WHEN excluded.name<>'' THEN excluded.name ELSE devices.name END,"
        "vendor=excluded.vendor,type=excluded.type,comment=excluded.comment,last_seen=excluded.last_seen";
    if (sqlite3_prepare_v2(g_db, q, -1, &st, NULL) == SQLITE_OK) {
        pips_sql_text(st, 1, r->ips); pips_sql_text(st, 2, r->mac); pips_sql_text(st, 3, r->name);
        pips_sql_text(st, 4, r->vendor); pips_sql_text(st, 5, r->type);
        pips_sql_text(st, 6, r->desc); sqlite3_bind_int64(st, 7, (sqlite3_int64)time(NULL));
        sqlite3_step(st);
    }
    sqlite3_finalize(st);
}
static void pips_monitor_load(void) {
    if (!g_db) return;
    sqlite3_stmt *st = NULL;
    const char *q = "SELECT m.ip,m.subnet,m.interval_sec,m.alive,m.last_ping,m.last_rtt,"
                    "COALESCE(d.name,''),COALESCE(d.mac,''),COALESCE(d.vendor,''),"
                    "COALESCE(d.type,''),COALESCE(d.comment,'') FROM monitoring m LEFT JOIN devices d ON d.ip=m.ip";
    if (sqlite3_prepare_v2(g_db, q, -1, &st, NULL) != SQLITE_OK) return;
    while (sqlite3_step(st) == SQLITE_ROW && g_nmon < PIPS_MAX_MON) {
        PipsMon *m = &g_mon[g_nmon++]; memset(m, 0, sizeof *m);
        const void *t;
#define READW(C,D,CAP) t = sqlite3_column_text16(st,(C)); if(t) lstrcpynW((D), (const WCHAR*)t, (CAP));
        READW(0,m->res.ips,16) READW(1,m->subnet,32)
        READW(6,m->res.name,64) READW(7,m->res.mac,18) READW(8,m->res.vendor,32)
        READW(9,m->res.type,24) READW(10,m->res.desc,128)
#undef READW
        WCHAR auth[40];
        if(ini_read(L"auth",m->res.mac[0]?m->res.mac:m->res.ips,auth,40))
            lstrcpynW(m->res.auth,auth,40);
        m->interval = sqlite3_column_int(st, 2); if (m->interval < 5) m->interval = 30;
        wsprintfW(m->res.monitor,L"%d sec",m->interval);
        m->res.alive = sqlite3_column_int(st, 3);
        m->last_ts = sqlite3_column_int64(st, 4); m->res.rtt = sqlite3_column_int(st, 5);
        parse_ip(m->res.ips, &m->res.ip);
        m->next_tick = GetTickCount() + (DWORD)(g_nmon * 100);
    }
    sqlite3_finalize(st);
    pips_subnet_refresh();
}
static void pips_ui_state_load(void) {
    if(!g_db)return;
    sqlite3_stmt *st=NULL;
    if(sqlite3_prepare_v2(g_db,"SELECT key,value FROM app_settings",-1,&st,NULL)!=SQLITE_OK)return;
    while(sqlite3_step(st)==SQLITE_ROW) {
        const char *key=(const char*)sqlite3_column_text(st,0);
        int value=sqlite3_column_int(st,1);
        if(key && !lstrcmpA(key,"scanner_expanded"))g_scanner_expanded=value!=0;
        if(key && !lstrcmpA(key,"monitor_expanded"))g_monitor_expanded=value!=0;
    }
    sqlite3_finalize(st);
}
static void pips_ui_state_save(void) {
    if(!g_db)return;
    sqlite3_stmt *st=NULL;
    const char *q="INSERT INTO app_settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value";
    if(sqlite3_prepare_v2(g_db,q,-1,&st,NULL)!=SQLITE_OK)return;
    sqlite3_bind_text(st,1,"scanner_expanded",-1,SQLITE_STATIC);
    sqlite3_bind_int(st,2,g_scanner_expanded);
    sqlite3_step(st);sqlite3_reset(st);sqlite3_clear_bindings(st);
    sqlite3_bind_text(st,1,"monitor_expanded",-1,SQLITE_STATIC);
    sqlite3_bind_int(st,2,g_monitor_expanded);
    sqlite3_step(st);sqlite3_finalize(st);
}
static void pips_monitor_add(RES *r, int interval) {
    int i;
    for (i = 0; i < g_nmon; i++) if (!lstrcmpW(g_mon[i].res.ips, r->ips)) break;
    if (i == g_nmon && g_nmon >= PIPS_MAX_MON) return;
    PipsMon *m = &g_mon[i];
    if (i == g_nmon) { memset(m, 0, sizeof *m); g_nmon++; }
    m->res = *r; m->interval = interval; m->next_tick = GetTickCount() + 300;
    wsprintfW(m->res.monitor,L"%d sec",interval);
    wsprintfW(r->monitor,L"%d sec",interval);
    for(int j=0;j<g_nres;j++)if(g_res[j]!=r && !lstrcmpW(g_res[j]->ips,r->ips))
        wsprintfW(g_res[j]->monitor,L"%d sec",interval);
    pips_default_subnet(r->ip, m->subnet);
    pips_device_store(r); pips_monitor_store(m); pips_subnet_refresh();
    if(!g_mon_batch){if (g_mon_mode) refill(); else invalidate_tabs();}
}
static void pips_monitor_remove(RES *r) {
    for (int i = 0; i < g_nmon; i++) if (!lstrcmpW(g_mon[i].res.ips, r->ips)) {
        for(int j=0;j<g_nres;j++)if(!lstrcmpW(g_res[j]->ips,r->ips))g_res[j]->monitor[0]=0;
        if (g_mon[i].pending) { /* pending result checks index and IP before updating */ }
        if (g_db) { sqlite3_stmt *st = NULL;
            if (sqlite3_prepare_v2(g_db, "DELETE FROM monitoring WHERE ip=?", -1, &st, NULL) == SQLITE_OK) {
                pips_sql_text(st, 1, r->ips); sqlite3_step(st);
            } sqlite3_finalize(st);
        }
        memmove(&g_mon[i], &g_mon[i+1], (g_nmon-i-1)*sizeof(g_mon[0])); g_nmon--;
        pips_subnet_refresh(); if(!g_mon_batch)refill(); break;
    }
}
static DWORD WINAPI pips_mon_worker(LPVOID payload) {
    PipsMonResult *result = (PipsMonResult *)payload;
    HANDLE icmp = IcmpCreateFile();
    if (icmp != INVALID_HANDLE_VALUE) {
        char data[16] = "pips-monitor"; BYTE reply[sizeof(ICMP_ECHO_REPLY)+64];
        DWORD n = IcmpSendEcho(icmp, htonl(result->ip), data, sizeof data, NULL, reply, sizeof reply, 1000);
        if (n) { ICMP_ECHO_REPLY *e = (ICMP_ECHO_REPLY*)reply;
            if (e->Status == IP_SUCCESS) { result->ok = 1; result->rtt = (int)e->RoundTripTime; }
        }
        IcmpCloseHandle(icmp);
    }
    if (!PostMessageW(g_wnd, WM_MONPING, 0, (LPARAM)result)) xfree(result);
    return 0;
}
static void pips_monitor_tick(void) {
    DWORD now = GetTickCount();
    for (int i = 0; i < g_nmon && g_mon_inflight < PIPS_MAX_INFLIGHT; i++) {
        PipsMon *m = &g_mon[i];
        if (m->pending || (LONG)(now - m->next_tick) < 0) continue;
        PipsMonResult *job = xalloc(sizeof *job); if (!job) break;
        job->index = i; job->ip = m->res.ip;
        HANDLE th = CreateThread(NULL, 0, pips_mon_worker, job, 0, NULL);
        if (!th) { xfree(job); break; }
        CloseHandle(th); m->pending = 1; g_mon_inflight++;
        m->next_tick = now + m->interval * 1000;
    }
}
static void pips_monitor_result(PipsMonResult *result) {
    if (g_mon_inflight > 0) g_mon_inflight--;
    /* Device may have been removed or indices shifted while the job was pending. */
    PipsMon *m = NULL;
    for (int i = 0; i < g_nmon; i++) if (g_mon[i].res.ip == result->ip) { m = &g_mon[i]; break; }
    if (m) {
        m->pending = 0;
        int prior = m->res.alive;
        if (result->ok) {
            m->failures = 0; m->successes++;
            if (m->successes >= 2) m->res.alive = 1;
            m->res.rtt = result->rtt;
            wsprintfW(m->res.ping, L"%d ms", result->rtt);
        } else {
            m->successes = 0; m->failures++;
            if (m->failures >= 3) m->res.alive = 0;
            m->res.rtt = -1;
            lstrcpyW(m->res.ping, L"Timeout");
        }
        m->last_ts = (sqlite3_int64)time(NULL);
        if (g_db) {
            sqlite3_stmt *st = NULL;
            if (sqlite3_prepare_v2(g_db,"INSERT INTO ping_history(ip,ts,rtt,ok) VALUES(?,?,?,?)",-1,&st,NULL)==SQLITE_OK) {
                pips_sql_text(st,1,m->res.ips); sqlite3_bind_int64(st,2,m->last_ts);
                sqlite3_bind_int(st,3,result->ok?result->rtt:-1); sqlite3_bind_int(st,4,result->ok);
                sqlite3_step(st);
            } sqlite3_finalize(st);
            if (prior != m->res.alive) {
                if (sqlite3_prepare_v2(g_db,"INSERT INTO events(ip,ts,event) VALUES(?,?,?)",-1,&st,NULL)==SQLITE_OK) {
                    pips_sql_text(st,1,m->res.ips); sqlite3_bind_int64(st,2,m->last_ts);
                    sqlite3_bind_text(st,3,m->res.alive?"Recovered":"Offline",-1,SQLITE_STATIC);
                    sqlite3_step(st);
                } sqlite3_finalize(st);
            }
        }
        pips_monitor_store(m);
        if (g_mon_mode) {
            LVFINDINFOW fi={0}; fi.flags=LVFI_PARAM; fi.lParam=(LPARAM)&m->res;
            int row=(int)SendMessageW(g_list,LVM_FINDITEMW,(WPARAM)-1,(LPARAM)&fi);
            if(row>=0) {
                LVITEMW it={0}; it.iItem=row;it.mask=LVIF_IMAGE;it.iImage=m->res.alive?0:1;
                SendMessageW(g_list,LVM_SETITEMW,0,(LPARAM)&it);
                LVITEMW sub={0};sub.iSubItem=C_PING;sub.pszText=m->res.ping;
                SendMessageW(g_list,LVM_SETITEMTEXTW,row,(LPARAM)&sub);
            }
        }
        invalidate_tabs();
    }
    xfree(result);
}
static void pips_monitor_prune(void) {
    if (!g_db) return;
    pips_db_exec("DELETE FROM ping_history WHERE ts < strftime('%s','now')-604800;");
    pips_db_exec("DELETE FROM events WHERE ts < strftime('%s','now')-604800;");
}
static int pips_backup_db(const WCHAR *path) {
    if (!g_db) return 0;
    sqlite3 *out = NULL;
    if (sqlite3_open16(path,&out)!=SQLITE_OK) { if(out) sqlite3_close(out); return 0; }
    sqlite3_backup *b = sqlite3_backup_init(out,"main",g_db,"main");
    int ok = 0;
    if (b) { int rc = sqlite3_backup_step(b,-1); ok = rc == SQLITE_DONE;
        sqlite3_backup_finish(b);
    }
    sqlite3_close(out); return ok;
}
static void pips_data_shutdown(void) {
    if (g_db) { sqlite3_close(g_db); g_db = NULL; }
}
