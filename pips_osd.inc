/* Retry missing camera OSD names in a bounded background queue after scanning. */
typedef struct { DWORD ip, generation; WCHAR name[64]; } PipsOsdJob;
static DWORD g_osd_targets[1024];
static int g_osd_total, g_osd_next, g_osd_active;
static volatile LONG g_osd_generation;
static DWORD WINAPI pips_osd_worker(LPVOID ctx) {
    PipsOsdJob *job=(PipsOsdJob*)ctx;
    for(int attempt=0;attempt<2;attempt++) {
        if(attempt)Sleep(5000);
        if(job->generation!=(DWORD)g_osd_generation)break;
        char buf[8192]; ONV o; memset(&o,0,sizeof o);
        WSDI w; memset(&w,0,sizeof w);
        wsd_find(htonl(job->ip),&w);
        onvif_query(job->ip,wsd_onvif(&w)?w.xaddr:"",1,buf,sizeof buf,&o,NULL,0);
        if(o.osd[0]) {MultiByteToWideChar(CP_UTF8,0,o.osd,-1,job->name,64);break;}
    }
    if(!PostMessageW(g_wnd,WM_OSDNAME,0,(LPARAM)job))xfree(job);
    return 0;
}
static void pips_osd_start_more(void) {
    while(g_osd_active<4 && g_osd_next<g_osd_total) {
        PipsOsdJob *job=xalloc(sizeof *job);if(!job)break;
        job->ip=g_osd_targets[g_osd_next++];job->generation=(DWORD)g_osd_generation;
        HANDLE th=CreateThread(NULL,0,pips_osd_worker,job,0,NULL);
        if(!th){xfree(job);break;}
        g_osd_active++;CloseHandle(th);
    }
}
static void pips_osd_start_scan_retry(void) {
    InterlockedIncrement(&g_osd_generation);
    g_osd_total=g_osd_next=0;g_osd_active=0;
    for(int i=0;i<g_nres&&g_osd_total<1024;i++) {
        RES *r=g_res[i];
        if(r->alive && !r->name[0] && !lstrcmpiW(r->type,L"IP camera"))
            g_osd_targets[g_osd_total++]=r->ip;
    }
    pips_osd_start_more();
}
static void pips_osd_finish(PipsOsdJob *job) {
    if(job->generation==(DWORD)g_osd_generation) {
        if(g_osd_active)g_osd_active--;
        if(job->name[0])for(int i=0;i<g_nres;i++)if(g_res[i]->ip==job->ip && !g_res[i]->name[0]) {
            RES *r=g_res[i];lstrcpynW(r->name,job->name,64);
            pips_device_store(r);
            LVFINDINFOW fi={0};fi.flags=LVFI_PARAM;fi.lParam=(LPARAM)r;
            int row=(int)SendMessageW(g_list,LVM_FINDITEMW,(WPARAM)-1,(LPARAM)&fi);
            if(row>=0) {LVITEMW sub={0};sub.iSubItem=C_NAME;sub.pszText=r->name;
                SendMessageW(g_list,LVM_SETITEMTEXTW,row,(LPARAM)&sub);}
            for(int k=0;k<g_nmon;k++)if(g_mon[k].res.ip==job->ip) {
                lstrcpynW(g_mon[k].res.name,job->name,64);break;
            }
            break;
        }
        pips_osd_start_more();
    }
    xfree(job);
}
