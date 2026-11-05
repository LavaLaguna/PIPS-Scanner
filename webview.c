/* ============================================================================
 *  Embedded IE / ActiveX viewer  (hosts the Windows WebBrowser control)
 *  - no external browser; renders inside our own window
 *  - ActiveX enabled, so NVR / camera plug-ins that need IE can load
 *  Only system DLLs: ole32, oleaut32, user32.
 * ==========================================================================*/
#ifndef COBJMACROS
#define COBJMACROS
#endif
#include <stddef.h>
#include <stdarg.h>
#include <ole2.h>
#include <exdisp.h>
#include <mshtmhst.h>
#include <mshtml.h>
#include <docobj.h>
#include <servprov.h>
#include <urlmon.h>
#include "vendor/webview2/WebView2.h"

/* ---- GUIDs (defined locally so we need no -luuid) ---- */
static const GUID xCLSID_WebBrowser  = {0x8856F961,0x340A,0x11D0,{0xA9,0x6B,0x00,0xC0,0x4F,0xD7,0x05,0xA2}};
static const GUID xIID_IWebBrowser2  = {0xD30C1661,0xCDAF,0x11D0,{0x8A,0x3E,0x00,0xC0,0x4F,0xC9,0xE2,0x6E}};
static const GUID xIID_IOleObject    = {0x00000112,0,0,{0xC0,0,0,0,0,0,0,0x46}};
static const GUID xIID_IOleInPlaceObject = {0x00000113,0,0,{0xC0,0,0,0,0,0,0,0x46}};
static const GUID xIID_IOleClientSite= {0x00000118,0,0,{0xC0,0,0,0,0,0,0,0x46}};
static const GUID xIID_IOleInPlaceSite={0x00000119,0,0,{0xC0,0,0,0,0,0,0,0x46}};
static const GUID xIID_IOleInPlaceFrame={0x00000116,0,0,{0xC0,0,0,0,0,0,0,0x46}};
static const GUID xIID_IOleWindow    = {0x00000114,0,0,{0xC0,0,0,0,0,0,0,0x46}};
static const GUID xIID_IUnknown      = {0x00000000,0,0,{0xC0,0,0,0,0,0,0,0x46}};
static const GUID xIID_IDispatch     = {0x00020400,0,0,{0xC0,0,0,0,0,0,0,0x46}};
static const GUID xDIID_DWebEvents2  = {0x34A715A0,0x6587,0x11D0,{0x92,0x4A,0x00,0x20,0xAF,0xC7,0xAC,0x4D}};
static const GUID xIID_ICPContainer  = {0xB196B284,0xBAB4,0x101A,{0xB6,0x9C,0x00,0xAA,0x00,0x34,0x1D,0x07}};
static const GUID xIID_IHTMLDocument2= {0x332C4425,0x26CB,0x11D0,{0xB4,0x83,0x00,0xC0,0x4F,0xD9,0x01,0x19}};
static const GUID xIID_IOleIPActiveObj = {0x00000117,0,0,{0xC0,0,0,0,0,0,0,0x46}};
static const GUID xIID_IServiceProvider= {0x6D5140C1,0x7436,0x11CE,{0x80,0x34,0x00,0xAA,0x00,0x60,0x09,0xFA}};
static const GUID xIID_ISecurityMgr    = {0x79EAC9EE,0xBAF9,0x11CE,{0x8C,0x82,0x00,0xAA,0x00,0x4B,0xA9,0x0B}};
#ifndef INET_E_DEFAULT_ACTION
#define INET_E_DEFAULT_ACTION 0x800C0011L
#endif
#ifndef URLPOLICY_ALLOW
#define URLPOLICY_ALLOW 0x00
#endif

typedef struct {
    IOleClientSite  cs;
    IOleInPlaceSite ips;
    IOleInPlaceFrame ipf;
    IServiceProvider sp;
    IInternetSecurityManager sm;
    HWND hwnd;
    IOleObject *obj;
} Site;

#define FROM_CS(p)  ((Site*)(p))
#define FROM_IPS(p) ((Site*)((char*)(p) - offsetof(Site, ips)))
#define FROM_IPF(p) ((Site*)((char*)(p) - offsetof(Site, ipf)))
#define FROM_SP(p)  ((Site*)((char*)(p) - offsetof(Site, sp)))

static int guid_eq(REFIID a, const GUID *b) { return IsEqualGUID(a, b); }

/* --- shared IUnknown for the site (ref held by caller; no real counting) --- */
static HRESULT STDMETHODCALLTYPE site_qi(Site *s, REFIID riid, void **ppv) {
    if (guid_eq(riid, &xIID_IUnknown) || guid_eq(riid, &xIID_IOleClientSite)) { *ppv = &s->cs; return S_OK; }
    if (guid_eq(riid, &xIID_IOleInPlaceSite)) { *ppv = &s->ips; return S_OK; }
    if (guid_eq(riid, &xIID_IOleWindow))      { *ppv = &s->ips; return S_OK; }
    if (guid_eq(riid, &xIID_IOleInPlaceFrame)){ *ppv = &s->ipf; return S_OK; }
    if (guid_eq(riid, &xIID_IServiceProvider)){ *ppv = &s->sp; return S_OK; }
    *ppv = NULL; return E_NOINTERFACE;
}

/* IOleClientSite */
static HRESULT STDMETHODCALLTYPE cs_QI(IOleClientSite *t, REFIID r, void **p){ return site_qi(FROM_CS(t), r, p); }
static ULONG   STDMETHODCALLTYPE cs_AddRef(IOleClientSite *t){ (void)t; return 1; }
static ULONG   STDMETHODCALLTYPE cs_Release(IOleClientSite *t){ (void)t; return 1; }
static HRESULT STDMETHODCALLTYPE cs_SaveObject(IOleClientSite *t){ (void)t; return S_OK; }
static HRESULT STDMETHODCALLTYPE cs_GetMoniker(IOleClientSite *t, DWORD a, DWORD b, IMoniker **m){ (void)t;(void)a;(void)b; *m=NULL; return E_NOTIMPL; }
static HRESULT STDMETHODCALLTYPE cs_GetContainer(IOleClientSite *t, IOleContainer **c){ (void)t; *c=NULL; return E_NOINTERFACE; }
static HRESULT STDMETHODCALLTYPE cs_ShowObject(IOleClientSite *t){ (void)t; return S_OK; }
static HRESULT STDMETHODCALLTYPE cs_OnShowWindow(IOleClientSite *t, BOOL b){ (void)t;(void)b; return S_OK; }
static HRESULT STDMETHODCALLTYPE cs_RequestNewObjectLayout(IOleClientSite *t){ (void)t; return E_NOTIMPL; }
static IOleClientSiteVtbl g_csv = {
    cs_QI, cs_AddRef, cs_Release, cs_SaveObject, cs_GetMoniker,
    cs_GetContainer, cs_ShowObject, cs_OnShowWindow, cs_RequestNewObjectLayout
};

/* IOleInPlaceSite */
static HRESULT STDMETHODCALLTYPE ips_QI(IOleInPlaceSite *t, REFIID r, void **p){ return site_qi(FROM_IPS(t), r, p); }
static ULONG   STDMETHODCALLTYPE ips_AddRef(IOleInPlaceSite *t){ (void)t; return 1; }
static ULONG   STDMETHODCALLTYPE ips_Release(IOleInPlaceSite *t){ (void)t; return 1; }
static HRESULT STDMETHODCALLTYPE ips_GetWindow(IOleInPlaceSite *t, HWND *w){ *w = FROM_IPS(t)->hwnd; return S_OK; }
static HRESULT STDMETHODCALLTYPE ips_ContextSensitiveHelp(IOleInPlaceSite *t, BOOL b){ (void)t;(void)b; return S_OK; }
static HRESULT STDMETHODCALLTYPE ips_CanInPlaceActivate(IOleInPlaceSite *t){ (void)t; return S_OK; }
static HRESULT STDMETHODCALLTYPE ips_OnInPlaceActivate(IOleInPlaceSite *t){ (void)t; return S_OK; }
static HRESULT STDMETHODCALLTYPE ips_OnUIActivate(IOleInPlaceSite *t){ (void)t; return S_OK; }
static HRESULT STDMETHODCALLTYPE ips_GetWindowContext(IOleInPlaceSite *t, IOleInPlaceFrame **frame,
        IOleInPlaceUIWindow **doc, LPRECT pos, LPRECT clip, LPOLEINPLACEFRAMEINFO fi) {
    Site *s = FROM_IPS(t);
    *frame = &s->ipf; *doc = NULL;
    GetClientRect(s->hwnd, pos);
    GetClientRect(s->hwnd, clip);
    fi->cb = sizeof(OLEINPLACEFRAMEINFO); fi->fMDIApp = FALSE; fi->hwndFrame = s->hwnd;
    fi->haccel = NULL; fi->cAccelEntries = 0;
    return S_OK;
}
static HRESULT STDMETHODCALLTYPE ips_Scroll(IOleInPlaceSite *t, SIZE s){ (void)t;(void)s; return E_NOTIMPL; }
static HRESULT STDMETHODCALLTYPE ips_OnUIDeactivate(IOleInPlaceSite *t, BOOL b){ (void)t;(void)b; return S_OK; }
static HRESULT STDMETHODCALLTYPE ips_OnInPlaceDeactivate(IOleInPlaceSite *t){ (void)t; return S_OK; }
static HRESULT STDMETHODCALLTYPE ips_DiscardUndoState(IOleInPlaceSite *t){ (void)t; return S_OK; }
static HRESULT STDMETHODCALLTYPE ips_DeactivateAndUndo(IOleInPlaceSite *t){ (void)t; return S_OK; }
static HRESULT STDMETHODCALLTYPE ips_OnPosRectChange(IOleInPlaceSite *t, LPCRECT r){ (void)t;(void)r; return S_OK; }
static IOleInPlaceSiteVtbl g_ipsv = {
    ips_QI, ips_AddRef, ips_Release, ips_GetWindow, ips_ContextSensitiveHelp,
    ips_CanInPlaceActivate, ips_OnInPlaceActivate, ips_OnUIActivate, ips_GetWindowContext,
    ips_Scroll, ips_OnUIDeactivate, ips_OnInPlaceDeactivate, ips_DiscardUndoState,
    ips_DeactivateAndUndo, ips_OnPosRectChange
};

/* IOleInPlaceFrame */
static HRESULT STDMETHODCALLTYPE ipf_QI(IOleInPlaceFrame *t, REFIID r, void **p){ return site_qi(FROM_IPF(t), r, p); }
static ULONG   STDMETHODCALLTYPE ipf_AddRef(IOleInPlaceFrame *t){ (void)t; return 1; }
static ULONG   STDMETHODCALLTYPE ipf_Release(IOleInPlaceFrame *t){ (void)t; return 1; }
static HRESULT STDMETHODCALLTYPE ipf_GetWindow(IOleInPlaceFrame *t, HWND *w){ *w = FROM_IPF(t)->hwnd; return S_OK; }
static HRESULT STDMETHODCALLTYPE ipf_ContextSensitiveHelp(IOleInPlaceFrame *t, BOOL b){ (void)t;(void)b; return S_OK; }
static HRESULT STDMETHODCALLTYPE ipf_GetBorder(IOleInPlaceFrame *t, LPRECT r){ (void)t;(void)r; return E_NOTIMPL; }
static HRESULT STDMETHODCALLTYPE ipf_RequestBorderSpace(IOleInPlaceFrame *t, LPCBORDERWIDTHS w){ (void)t;(void)w; return E_NOTIMPL; }
static HRESULT STDMETHODCALLTYPE ipf_SetBorderSpace(IOleInPlaceFrame *t, LPCBORDERWIDTHS w){ (void)t;(void)w; return E_NOTIMPL; }
static HRESULT STDMETHODCALLTYPE ipf_SetActiveObject(IOleInPlaceFrame *t, IOleInPlaceActiveObject *o, LPCOLESTR n){ (void)t;(void)o;(void)n; return S_OK; }
static HRESULT STDMETHODCALLTYPE ipf_InsertMenus(IOleInPlaceFrame *t, HMENU m, LPOLEMENUGROUPWIDTHS w){ (void)t;(void)m;(void)w; return E_NOTIMPL; }
static HRESULT STDMETHODCALLTYPE ipf_SetMenu(IOleInPlaceFrame *t, HMENU m, HOLEMENU h, HWND w){ (void)t;(void)m;(void)h;(void)w; return S_OK; }
static HRESULT STDMETHODCALLTYPE ipf_RemoveMenus(IOleInPlaceFrame *t, HMENU m){ (void)t;(void)m; return S_OK; }
static HRESULT STDMETHODCALLTYPE ipf_SetStatusText(IOleInPlaceFrame *t, LPCOLESTR s){ (void)t;(void)s; return S_OK; }
static HRESULT STDMETHODCALLTYPE ipf_EnableModeless(IOleInPlaceFrame *t, BOOL b){ (void)t;(void)b; return S_OK; }
static HRESULT STDMETHODCALLTYPE ipf_TranslateAccelerator(IOleInPlaceFrame *t, LPMSG m, WORD w){ (void)t;(void)m;(void)w; return S_FALSE; }
static IOleInPlaceFrameVtbl g_ipfv = {
    ipf_QI, ipf_AddRef, ipf_Release, ipf_GetWindow, ipf_ContextSensitiveHelp,
    ipf_GetBorder, ipf_RequestBorderSpace, ipf_SetBorderSpace, ipf_SetActiveObject,
    ipf_InsertMenus, ipf_SetMenu, ipf_RemoveMenus, ipf_SetStatusText,
    ipf_EnableModeless, ipf_TranslateAccelerator
};

/* IInternetSecurityManager: allow ActiveX / scripts / downloads on the user's own LAN devices */
static HRESULT STDMETHODCALLTYPE sm_QI(IInternetSecurityManager *t, REFIID r, void **p){
    if (guid_eq(r,&xIID_IUnknown)||guid_eq(r,&xIID_ISecurityMgr)){ *p=t; return S_OK; } *p=NULL; return E_NOINTERFACE; }
static ULONG STDMETHODCALLTYPE sm_AddRef(IInternetSecurityManager *t){ (void)t; return 1; }
static ULONG STDMETHODCALLTYPE sm_Release(IInternetSecurityManager *t){ (void)t; return 1; }
static HRESULT STDMETHODCALLTYPE sm_SetSecuritySite(IInternetSecurityManager *t, IInternetSecurityMgrSite *s){ (void)t;(void)s; return INET_E_DEFAULT_ACTION; }
static HRESULT STDMETHODCALLTYPE sm_GetSecuritySite(IInternetSecurityManager *t, IInternetSecurityMgrSite **s){ (void)t; if(s)*s=NULL; return INET_E_DEFAULT_ACTION; }
static HRESULT STDMETHODCALLTYPE sm_MapUrlToZone(IInternetSecurityManager *t, LPCWSTR u, DWORD *z, DWORD f){ (void)t;(void)u;(void)f; if(z)*z=1; return S_OK; }
static HRESULT STDMETHODCALLTYPE sm_GetSecurityId(IInternetSecurityManager *t, LPCWSTR u, BYTE *b, DWORD *cb, DWORD_PTR r){ (void)t;(void)u;(void)b;(void)cb;(void)r; return INET_E_DEFAULT_ACTION; }
static HRESULT STDMETHODCALLTYPE sm_ProcessUrlAction(IInternetSecurityManager *t, LPCWSTR u, DWORD act, BYTE *pol, DWORD cbpol, BYTE *ctx, DWORD cbctx, DWORD f, DWORD rr){
    (void)t;(void)u;(void)act;(void)ctx;(void)cbctx;(void)f;(void)rr;
    if (pol && cbpol >= sizeof(DWORD)) { *(DWORD*)pol = URLPOLICY_ALLOW; return S_OK; }
    return S_OK;
}
static HRESULT STDMETHODCALLTYPE sm_QueryCustomPolicy(IInternetSecurityManager *t, LPCWSTR u, REFGUID g, BYTE **pp, DWORD *cb, BYTE *c, DWORD cc, DWORD r){ (void)t;(void)u;(void)g;(void)pp;(void)cb;(void)c;(void)cc;(void)r; return INET_E_DEFAULT_ACTION; }
static HRESULT STDMETHODCALLTYPE sm_SetZoneMapping(IInternetSecurityManager *t, DWORD z, LPCWSTR p, DWORD f){ (void)t;(void)z;(void)p;(void)f; return INET_E_DEFAULT_ACTION; }
static HRESULT STDMETHODCALLTYPE sm_GetZoneMappings(IInternetSecurityManager *t, DWORD z, IEnumString **e, DWORD f){ (void)t;(void)z;(void)e;(void)f; return INET_E_DEFAULT_ACTION; }
static IInternetSecurityManagerVtbl g_smv = {
    sm_QI, sm_AddRef, sm_Release, sm_SetSecuritySite, sm_GetSecuritySite, sm_MapUrlToZone,
    sm_GetSecurityId, sm_ProcessUrlAction, sm_QueryCustomPolicy, sm_SetZoneMapping, sm_GetZoneMappings
};

/* IServiceProvider: hand the browser our security manager */
static HRESULT STDMETHODCALLTYPE sp_QI(IServiceProvider *t, REFIID r, void **p){ return site_qi(FROM_SP(t), r, p); }
static ULONG STDMETHODCALLTYPE sp_AddRef(IServiceProvider *t){ (void)t; return 1; }
static ULONG STDMETHODCALLTYPE sp_Release(IServiceProvider *t){ (void)t; return 1; }
static HRESULT STDMETHODCALLTYPE sp_QueryService(IServiceProvider *t, REFGUID svc, REFIID riid, void **pp){
    (void)t; (void)svc; (void)riid;
    /* Return nothing: let the WebBrowser control use Windows' normal Internet security-zone
       configuration (inetcpl.cpl), exactly like IE / Edge IE mode. Overriding it here with an
       allow-all security manager suppressed the ActiveX run/permission behaviour. */
    if (pp) *pp = NULL;
    return E_NOINTERFACE;
}
static IServiceProviderVtbl g_spv = { sp_QI, sp_AddRef, sp_Release, sp_QueryService };

/* ---- per-window viewer state ---- */
typedef struct {
    Site site;
    IOleObject *obj;
    IWebBrowser2 *wb;
    IOleInPlaceObject *ipo;
    IOleInPlaceActiveObject *pao;
    HWND addr, go, status, edge;
    WCHAR fuser[64], fpass[64];          /* credentials to auto-fill into the login form */
    WCHAR credential_host[128];          /* never autofill on a redirected, unrelated host */
    int fill_tries, typed, handed;      /* typed: ActiveX login typed once; handed: sent to modern window */
    IDispatch sink;                      /* DWebBrowserEvents2 sink (lpVtbl first) */
    IConnectionPoint *cp; DWORD cookie;
    ICoreWebView2Controller *wvctl;
    ICoreWebView2 *wv;
    ICoreWebView2Environment *wvenv;
    int engine; /* 0 IE, 1 WebView2, 2 WebView2 initializing */
    int wv_fills;
} View;
#define VIEW_FROM_SINK(p) ((View *)((char *)(p) - offsetof(View, sink)))

static View *g_views[16]; static int g_nviews;
static void modern_start(View *v);
static void modern_fill(View *v);
static void modern_size(View *v);
static void modern_close(View *v);
static void modern_restore_ie(View *v);

/* run a JS snippet in the page to drop the username / password into the login form */
static void vlog(const char *fmt, ...);
/* fill the login form (incl. same-origin iframes), fire input/change events, report how many fields set */
static int body_attr(IHTMLDocument2 *d2, const WCHAR *name) {
    int val = 0; IHTMLElement *bd = NULL;
    if (SUCCEEDED(IHTMLDocument2_get_body(d2, &bd)) && bd) {
        VARIANT av; VariantInit(&av); BSTR an = SysAllocString(name);
        if (SUCCEEDED(bd->lpVtbl->getAttribute(bd, an, 0, &av))) {
            if (av.vt == VT_BSTR && av.bstrVal) val = _wtoi(av.bstrVal); else if (av.vt == VT_I4) val = av.lVal;
        }
        VariantClear(&av); SysFreeString(an); bd->lpVtbl->Release(bd);
    }
    return val;
}
/* probe + fill: returns HTML fields filled; *ax = ActiveX objects on the page (first one is focused when
   nothing could be filled); *broken = page rendered nothing usable (modern site IE cannot run) */
static int view_autofill(View *v, int *ax, int *broken) {
    *ax = 0; *broken = 0;
    if (!v->wb) return 0;
    IDispatch *doc = NULL;
    HRESULT hd = IWebBrowser2_get_Document(v->wb, &doc);
    if (FAILED(hd) || !doc) { vlog("autofill try%d: get_Document hr=0x%08X", v->fill_tries, (unsigned)hd); return 0; }
    int filled = 0;
    IHTMLDocument2 *d2 = NULL;
    if (SUCCEEDED(doc->lpVtbl->QueryInterface(doc, &xIID_IHTMLDocument2, (void **)&d2)) && d2) {
        IHTMLWindow2 *win = NULL;
        if (SUCCEEDED(IHTMLDocument2_get_parentWindow(d2, &win)) && win) {
            /* escape for a JS single-quoted literal (quote, backslash, CR, LF) */
            WCHAR eu[200], ep[200]; int a2 = 0, b2 = 0;
            for (int i = 0; v->fuser[i] && a2 < 194; i++) { WCHAR c = v->fuser[i]; if (c=='\\'||c=='\''){eu[a2++]='\\';} if(c=='\r'||c=='\n')c=' '; eu[a2++]=c; } eu[a2]=0;
            for (int i = 0; v->fpass[i] && b2 < 194; i++) { WCHAR c = v->fpass[i]; if (c=='\\'||c=='\''){ep[b2++]='\\';} if(c=='\r'||c=='\n')c=' '; ep[b2++]=c; } ep[b2]=0;
            WCHAR *js = (WCHAR *)HeapAlloc(GetProcessHeap(), 0, 4096 * sizeof(WCHAR));
            if (js) {
                /* build by concatenation - wsprintfW caps output at 1024 chars and would truncate the script */
                js[0] = 0;
                lstrcatW(js, L"(function(){var U='"); lstrcatW(js, eu); lstrcatW(js, L"',P='"); lstrcatW(js, ep); lstrcatW(js, L"';var N=0,A=0,I=0,F=0,T=0,fo=null;");
                lstrcatW(js, L"function ev(el,t){try{var e=document.createEvent('HTMLEvents');e.initEvent(t,true,false);el.dispatchEvent(e);}catch(x){try{el.fireEvent('on'+t);}catch(y){}}}");
                lstrcatW(js, L"function set(el,val){el.value=val;ev(el,'input');ev(el,'change');ev(el,'keyup');N++;}");
                lstrcatW(js, L"function fill(d){try{var ob=d.getElementsByTagName('object'),em=d.getElementsByTagName('embed');A+=ob.length+em.length;if(!fo&&ob.length)fo=ob[0];if(!fo&&em.length)fo=em[0];");
                lstrcatW(js, L"try{F+=d.getElementsByTagName('iframe').length+d.getElementsByTagName('frame').length;T+=((d.body&&(d.body.innerText||''))||'').replace(/\\s+/g,'').length;}catch(x){}");
                lstrcatW(js, L"var ins=d.getElementsByTagName('input');I+=ins.length;if(!U&&!P)return;var uf=null,pf=null,pfi=-1;");
                lstrcatW(js, L"for(var i=0;i<ins.length;i++){var t=(ins[i].type||'').toLowerCase();if(t=='password'&&!pf){pf=ins[i];pfi=i;}}");
                lstrcatW(js, L"for(var i=0;i<ins.length;i++){var t=(ins[i].type||'').toLowerCase();var n=((ins[i].name||'')+' '+(ins[i].id||'')+' '+(ins[i].className||'')).toLowerCase();");
                lstrcatW(js, L"if((t=='text'||t=='')&&(n.indexOf('user')>=0||n.indexOf('name')>=0||n.indexOf('account')>=0||n.indexOf('login')>=0||ins[i].value=='admin')){uf=ins[i];break;}}");
                lstrcatW(js, L"if(!uf&&pfi>0){for(var i=pfi-1;i>=0;i--){var t=(ins[i].type||'').toLowerCase();if(t=='text'||t==''){uf=ins[i];break;}}}");
                lstrcatW(js, L"if(!uf){for(var i=0;i<ins.length;i++){var t=(ins[i].type||'').toLowerCase();if(t=='text'||t==''){uf=ins[i];break;}}}");
                lstrcatW(js, L"if(uf)set(uf,U);if(pf)set(pf,P);}catch(e){}}");
                lstrcatW(js, L"fill(document);try{for(var f=0;f<window.frames.length;f++){try{fill(window.frames[f].document);try{var g=window.frames[f].frames;for(var k=0;k<g.length;k++){try{fill(g[k].document);}catch(e){}}}catch(e){}}catch(e){}}}catch(e){}");
                /* report count on a body attribute instead of window.name: some devices (UNV) use
                   window.name for their own frame messaging, and clobbering it broke their pages. */
                lstrcatW(js, L"if(!N&&fo&&(U||P)){try{fo.focus();}catch(e){}}");
                lstrcatW(js, L"try{var b=document.body;if(b){b.setAttribute('data-ipsf',''+N);b.setAttribute('data-ipsa',''+A);");
                lstrcatW(js, L"b.setAttribute('data-ipsm',(!A&&!I&&!F&&T<40)?'1':'0');}}catch(e){}})();");
                BSTR sc = SysAllocString(js), lang = SysAllocString(L"JavaScript");
                VARIANT res; VariantInit(&res);
                HRESULT he = IHTMLWindow2_execScript(win, sc, lang, &res);
                VariantClear(&res); SysFreeString(sc); SysFreeString(lang);
                filled = body_attr(d2, L"data-ipsf"); *ax = body_attr(d2, L"data-ipsa"); *broken = body_attr(d2, L"data-ipsm");
                vlog("probe try%d: hr=0x%08X filled=%d activex=%d broken=%d", v->fill_tries, (unsigned)he, filled, *ax, *broken);
                HeapFree(GetProcessHeap(), 0, js);
            }
            win->lpVtbl->Release(win);
        }
        d2->lpVtbl->Release(d2);
    }
    doc->lpVtbl->Release(doc);
    return filled;
}

/* ---- DWebBrowserEvents2 sink (IDispatch) ---- */
static HRESULT STDMETHODCALLTYPE ev_QI(IDispatch *t, REFIID r, void **p) {
    if (IsEqualGUID(r, &xIID_IUnknown) || IsEqualGUID(r, &xIID_IDispatch) || IsEqualGUID(r, &xDIID_DWebEvents2)) { *p = t; return S_OK; }
    *p = NULL; return E_NOINTERFACE;
}
static ULONG STDMETHODCALLTYPE ev_AddRef(IDispatch *t) { (void)t; return 1; }
static ULONG STDMETHODCALLTYPE ev_Release(IDispatch *t) { (void)t; return 1; }
static HRESULT STDMETHODCALLTYPE ev_GetTICount(IDispatch *t, UINT *n) { (void)t; if (n) *n = 0; return S_OK; }
static HRESULT STDMETHODCALLTYPE ev_GetTI(IDispatch *t, UINT i, LCID l, ITypeInfo **ti) { (void)t;(void)i;(void)l; if (ti) *ti = NULL; return E_NOTIMPL; }
static HRESULT STDMETHODCALLTYPE ev_GetIDs(IDispatch *t, REFIID r, LPOLESTR *n, UINT c, LCID l, DISPID *d) { (void)t;(void)r;(void)n;(void)c;(void)l;(void)d; return E_NOTIMPL; }
static HRESULT STDMETHODCALLTYPE ev_Invoke(IDispatch *t, DISPID id, REFIID r, LCID l, WORD f, DISPPARAMS *dp, VARIANT *res, EXCEPINFO *ei, UINT *ea) {
    (void)r;(void)l;(void)f;(void)dp;(void)res;(void)ei;(void)ea;
    if (id == 259 /* DISPID_DOCUMENTCOMPLETE */) { View *v = VIEW_FROM_SINK(t); v->fill_tries = 0; SetTimer(v->site.hwnd, 1, 300, NULL); }
    return S_OK;
}
static IDispatchVtbl g_evv = { ev_QI, ev_AddRef, ev_Release, ev_GetTICount, ev_GetTI, ev_GetIDs, ev_Invoke };

static int VS(int v);
static HFONT view_font(void);

enum { VID_ADDR = 1, VID_GO, VID_BACK, VID_FWD, VID_RELOAD, VID_STOP, VID_LOGIN, VID_MODERN };
static void ie_set_emulation(DWORD val) {
    WCHAR exe[MAX_PATH]; GetModuleFileNameW(NULL, exe, MAX_PATH);
    WCHAR *base = exe; for (WCHAR *q = exe; *q; q++) if (*q == '\\') base = q + 1;
    HKEY k;
    if (RegCreateKeyExW(HKEY_CURRENT_USER,
        L"Software\\Microsoft\\Internet Explorer\\Main\\FeatureControl\\FEATURE_BROWSER_EMULATION",
        0, NULL, 0, KEY_SET_VALUE, NULL, &k, NULL) == ERROR_SUCCESS) {
        RegSetValueExW(k, base, 0, REG_DWORD, (const BYTE *)&val, sizeof val); RegCloseKey(k);
    }
}

static void view_navigate(View *v, const WCHAR *url) {
    if (v->engine == 1 && v->wv) { ICoreWebView2_Navigate(v->wv, url); return; }
    if (v->engine == 2) return;
    if (!v->wb) return;
    VARIANT vu, ve;
    VariantInit(&vu); VariantInit(&ve);
    vu.vt = VT_BSTR; vu.bstrVal = SysAllocString(url);
    IWebBrowser2_Navigate2(v->wb, &vu, &ve, &ve, &ve, &ve);
    VariantClear(&vu);
}

#include "webview2_host.inc"

/* Type text into whatever control has keyboard focus (ActiveX logins have no DOM to fill). */
static void view_type(const WCHAR *s) {
    for (; *s; s++) {
        INPUT in[2] = {0};
        in[0].type = in[1].type = INPUT_KEYBOARD;
        in[0].ki.wScan = in[1].ki.wScan = *s;
        in[0].ki.dwFlags = KEYEVENTF_UNICODE; in[1].ki.dwFlags = KEYEVENTF_UNICODE | KEYEVENTF_KEYUP;
        SendInput(2, in, sizeof(INPUT));
    }
}
static void view_key(WORD vk) {
    INPUT in[2] = {0};
    in[0].type = in[1].type = INPUT_KEYBOARD;
    in[0].ki.wVk = in[1].ki.wVk = vk; in[1].ki.dwFlags = KEYEVENTF_KEYUP;
    SendInput(2, in, sizeof(INPUT));
}
/* hand a page IE cannot render to a modern (Chromium) app window: chromeless, so it feels like this viewer */
static void view_open_modern(View *v) {
    if (v->engine) return;
    modern_start(v);
    if (v->engine) {
        KillTimer(v->site.hwnd, 1);
        if (v->ipo) IOleInPlaceObject_InPlaceDeactivate(v->ipo);
        SetWindowTextW(v->site.hwnd, L"Viewer  -  WebView2");
        if (v->edge) InvalidateRect(v->edge, NULL, TRUE);
    }
}
static void view_toggle_edge(View *v) {
    if (v->engine) {
        WCHAR u[512]; GetWindowTextW(v->addr, u, 512);
        modern_restore_ie(v);
        v->handed = 1; /* avoid instantly auto-switching the same IE page */
        v->typed = 0;
        SetWindowTextW(v->site.hwnd, L"Viewer  -  IE / ActiveX");
        if (u[0]) view_navigate(v, u);
    } else view_open_modern(v);
    if (v->edge) InvalidateRect(v->edge, NULL, TRUE);
}
static void view_type_login(View *v) {           /* ActiveX login: page focused the control, now type */
    view_type(v->fuser); view_key(VK_TAB); view_type(v->fpass); view_key(VK_RETURN);
    v->typed = 1; vlog("typed credentials into ActiveX control");
}

static void view_size(View *v) {
    RECT rc; GetClientRect(v->site.hwnd, &rc);
    int top = VS(30), bot = VS(22);
    RECT r = { 0, top, rc.right, rc.bottom - bot };
    if (v->ipo && !v->engine) IOleInPlaceObject_SetObjectRects(v->ipo, &r, &r);
    modern_size(v);
    int ax = VS(272), gw = VS(34);
    MoveWindow(v->addr, ax, VS(4), rc.right - ax - gw - VS(8), VS(22), TRUE);
    MoveWindow(v->go, rc.right - gw - VS(4), VS(4), gw, VS(22), TRUE);
    if (v->status) MoveWindow(v->status, 0, rc.bottom - bot, rc.right, bot, TRUE);
}

static LRESULT CALLBACK view_proc(HWND w, UINT m, WPARAM wp, LPARAM lp) {
    View *v = (View *)GetWindowLongPtrW(w, GWLP_USERDATA);
    switch (m) {
    case WM_DRAWITEM:
        if (v && ((DRAWITEMSTRUCT *)lp)->CtlID == VID_MODERN) {
            DRAWITEMSTRUCT *di = (DRAWITEMSTRUCT *)lp;
            int active = v->engine != 0;
            HBRUSH bg = CreateSolidBrush(active ? RGB(191, 225, 248) : GetSysColor(COLOR_BTNFACE));
            FillRect(di->hDC, &di->rcItem, bg); DeleteObject(bg);
            DrawEdge(di->hDC, &di->rcItem, (di->itemState & ODS_SELECTED) ? EDGE_SUNKEN : EDGE_RAISED, BF_RECT);
            SetBkMode(di->hDC, TRANSPARENT);
            SetTextColor(di->hDC, RGB(25, 55, 80));
            DrawTextW(di->hDC, L"Edge", -1, &di->rcItem, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
            if (di->itemState & ODS_FOCUS) DrawFocusRect(di->hDC, &di->rcItem);
            return TRUE;
        }
        break;
    case WM_SIZE: if (v) view_size(v); return 0;
    case WM_TIMER:
        if (v && wp == 2) { if (++v->wv_fills > 12) KillTimer(w, 2); else modern_fill(v); return 0; }
        if (v && wp == 1) {
            int ax, broken, fl = view_autofill(v, &ax, &broken), creds = v->fuser[0] || v->fpass[0], done = 0;
            if (fl > 0) done = 1;
            else if (ax > 0 && creds && !v->typed) {
                if (GetForegroundWindow() == w) { view_type_login(v); done = 1; }   /* never type into another app */
            } else if (broken && v->fill_tries >= 6 && !v->handed) {           /* ~2 s of nothing rendered */
                view_open_modern(v); v->handed = v->engine != 0;
            }
            if (done || ++v->fill_tries >= 15) KillTimer(w, 1);
        }
        return 0;
    case WM_SETFOCUS: if (v && v->site.hwnd) { RECT r; GetClientRect(w,&r);} return 0;
    case WM_COMMAND:
        if (!v) break;
        switch (LOWORD(wp)) {
        case VID_GO:
            { WCHAR u[512]; GetWindowTextW(v->addr, u, 512); if (u[0]) view_navigate(v, u); }
            break;
        case VID_BACK: if (v->engine == 1) ICoreWebView2_GoBack(v->wv); else if (v->wb) IWebBrowser2_GoBack(v->wb); break;
        case VID_FWD: if (v->engine == 1) ICoreWebView2_GoForward(v->wv); else if (v->wb) IWebBrowser2_GoForward(v->wb); break;
        case VID_RELOAD: if (v->engine == 1) ICoreWebView2_Reload(v->wv); else if (v->wb) IWebBrowser2_Refresh(v->wb); break;
        case VID_STOP: if (v->engine == 1) ICoreWebView2_Stop(v->wv); else if (v->wb) IWebBrowser2_Stop(v->wb); break;
        case VID_LOGIN:          /* fill HTML form now; ActiveX login: type into the control at once */
            if (v->fuser[0] || v->fpass[0]) {
                if (v->engine == 1) modern_fill(v);
                else { int ax, broken, fl = view_autofill(v, &ax, &broken); if (fl == 0) view_type_login(v); }
            } else {
                MessageBoxW(w, L"No camera credentials were supplied for this device.\n"
                               L"Open it from the list after setting a Cameras profile in Login\u2026,"
                               L" or type the user name and password on the page.",
                            L"Login", MB_ICONINFORMATION);
            }
            break;
        case VID_MODERN: view_toggle_edge(v); break;
        }
        return 0;
    case WM_DESTROY:
        if (v) {
            modern_close(v);
            for (int i = 0; i < g_nviews; i++) if (g_views[i] == v) { g_views[i] = g_views[--g_nviews]; break; }
            if (v->cp) { if (v->cookie) IConnectionPoint_Unadvise(v->cp, v->cookie); v->cp->lpVtbl->Release(v->cp); }
            if (v->pao) v->pao->lpVtbl->Release(v->pao);
            if (v->ipo) IOleInPlaceObject_Release(v->ipo);
            if (v->wb)  IWebBrowser2_Release(v->wb);
            if (v->obj) { IOleObject_Close(v->obj, OLECLOSE_NOSAVE); IOleObject_SetClientSite(v->obj, NULL); IOleObject_Release(v->obj); }
            HeapFree(GetProcessHeap(), 0, v);
            SetWindowLongPtrW(w, GWLP_USERDATA, 0);
        }
        if (g_nviews == 0) wv_unload_embedded();
        if (g_view_standalone && g_nviews == 0) PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcW(w, m, wp, lp);
}

/* enter-key in the address bar -> navigate */
static WNDPROC g_addr_proc;
static LRESULT CALLBACK addr_proc(HWND h, UINT m, WPARAM wp, LPARAM lp) {
    if (m == WM_KEYDOWN && wp == VK_RETURN) {
        SendMessageW(GetParent(h), WM_COMMAND, MAKEWPARAM(VID_GO, 0), 0);
        return 0;
    }
    return CallWindowProcW(g_addr_proc, h, m, wp, lp);
}

static void vlog(const char *fmt, ...) {
    WCHAR path[MAX_PATH]; DWORD n = GetModuleFileNameW(NULL, path, MAX_PATH - 20);
    while (n && path[n - 1] != '\\') n--;
    lstrcpyW(path + n, L"ipscan-viewer.log");
    HANDLE f = CreateFileW(path, FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_ALWAYS, 0, NULL);
    if (f == INVALID_HANDLE_VALUE) return;
    SetFilePointer(f, 0, NULL, FILE_END);
    char buf[512]; va_list ap; va_start(ap, fmt);
    int len = wvsprintfA(buf, fmt, ap); va_end(ap);
    DWORD wr; WriteFile(f, buf, len, &wr, NULL); WriteFile(f, "\r\n", 2, &wr, NULL);
    CloseHandle(f);
}

int viewer_pretranslate(MSG *m) {
    HWND root = GetAncestor(m->hwnd, GA_ROOT);
    for (int i = 0; i < g_nviews; i++) {
        View *v = g_views[i];
        if (v->site.hwnd != root) continue;
        /* let the address bar keep its own typing/Enter */
        if (m->hwnd == v->addr) return 0;
        if (!v->engine && v->pao && v->pao->lpVtbl->TranslateAccelerator(v->pao, m) == S_OK) return 1;
        return IsDialogMessageW(root, m) ? 1 : 0;
    }
    return 0;
}

void open_viewer(HWND parent, HINSTANCE hi, const WCHAR *ip, const WCHAR *user, const WCHAR *pass) {
    static int reg;
    if (!reg) {
        WNDCLASSEXW wc = {0};
        wc.cbSize = sizeof wc; wc.lpfnWndProc = view_proc; wc.hInstance = hi;
        wc.hCursor = LoadCursor(NULL, IDC_ARROW); wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
        wc.hIcon = LoadIconW(hi, MAKEINTRESOURCEW(1));
        wc.lpszClassName = L"IpScanViewer";
        RegisterClassExW(&wc); reg = 1;
    }
    ie_set_emulation(11000);
    WCHAR title[96], url[64];
    wsprintfW(title, L"Viewer  -  %s   (IE / ActiveX)", ip);
    wsprintfW(url, L"http://%s/", ip);

    HWND w = CreateWindowExW(0, L"IpScanViewer", title, WS_OVERLAPPEDWINDOW | WS_CLIPCHILDREN,
                             CW_USEDEFAULT, CW_USEDEFAULT, VS(1000), VS(720), parent, NULL, hi, NULL);
    if (!w) return;
    View *v = (View *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(View));
    if (!v) { DestroyWindow(w); return; }
    v->site.cs.lpVtbl = &g_csv;
    v->site.ips.lpVtbl = &g_ipsv;
    v->site.ipf.lpVtbl = &g_ipfv;
    v->site.sp.lpVtbl = &g_spv;
    v->site.sm.lpVtbl = &g_smv;
    v->site.hwnd = w;
    v->sink.lpVtbl = &g_evv;
    if (user) lstrcpynW(v->fuser, user, 64);
    if (pass) lstrcpynW(v->fpass, pass, 64);
    lstrcpynW(v->credential_host, ip, 128);
    if (g_nviews < 16) g_views[g_nviews++] = v;
    SetWindowLongPtrW(w, GWLP_USERDATA, (LONG_PTR)v);

    HFONT f = view_font();
    HWND bar;
#define TB(txt, id, x, cx) bar = CreateWindowExW(0, L"BUTTON", txt, WS_CHILD|WS_VISIBLE, VS(x), VS(4), VS(cx), VS(22), w, (HMENU)(INT_PTR)id, hi, NULL); SendMessageW(bar, WM_SETFONT,(WPARAM)f,TRUE);
    TB(L"◀", VID_BACK, 4, 30)
    TB(L"▶", VID_FWD, 36, 30)
    TB(L"↻", VID_RELOAD, 68, 30)
    TB(L"Stop", VID_STOP, 100, 44)
    TB(L"Login", VID_LOGIN, 146, 52)
    TB(L"Edge", VID_MODERN, 202, 66)
#undef TB
    v->edge = bar;
    SetWindowLongPtrW(v->edge, GWL_STYLE, GetWindowLongPtrW(v->edge, GWL_STYLE) | BS_OWNERDRAW);
    v->addr = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", url, WS_CHILD|WS_VISIBLE|ES_AUTOHSCROLL,
                              VS(272), VS(4), VS(400), VS(22), w, (HMENU)VID_ADDR, hi, NULL);
    SendMessageW(v->addr, WM_SETFONT, (WPARAM)f, TRUE);
    g_addr_proc = (WNDPROC)SetWindowLongPtrW(v->addr, GWLP_WNDPROC, (LONG_PTR)addr_proc);
    v->go = CreateWindowExW(0, L"BUTTON", L"Go", WS_CHILD|WS_VISIBLE|BS_DEFPUSHBUTTON, 0,0,0,0, w, (HMENU)VID_GO, hi, NULL);
    SendMessageW(v->go, WM_SETFONT, (WPARAM)f, TRUE);

    vlog("=== viewer open (%s) ===", sizeof(void*) == 8 ? "x64" : "x86");
    HRESULT hr = CoCreateInstance(&xCLSID_WebBrowser, NULL, CLSCTX_INPROC_SERVER,
                                  &xIID_IOleObject, (void **)&v->obj);
    vlog("CoCreateInstance(WebBrowser) hr=0x%08X obj=%p", (unsigned)hr, (void*)v->obj);
    if (FAILED(hr) || !v->obj) {
        MessageBoxW(w, L"The Internet Explorer web control is not available on this system.",
                    L"Viewer", MB_ICONWARNING);
        ShowWindow(w, SW_SHOW);
        return;
    }
    IOleObject_SetClientSite(v->obj, &v->site.cs);
    OleSetContainedObject((IUnknown *)v->obj, TRUE);
    RECT rc; GetClientRect(w, &rc);
    RECT pos = { 0, VS(30), rc.right, rc.bottom - VS(22) };
    hr = IOleObject_DoVerb(v->obj, OLEIVERB_INPLACEACTIVATE, NULL, &v->site.cs, 0, w, &pos);
    vlog("DoVerb(INPLACEACTIVATE) hr=0x%08X", (unsigned)hr);
    hr = IOleObject_QueryInterface(v->obj, &xIID_IWebBrowser2, (void **)&v->wb);
    vlog("QI(IWebBrowser2) hr=0x%08X wb=%p", (unsigned)hr, (void*)v->wb);
    if (v->wb) {
        /* Silent mode: suppress IE's script-error / security modal dialogs. These pop up on
           camera/NVR pages (e.g. UNV frame.js "Can't execute code from a freed script" when
           switching channels) and, being modal, freeze the viewer's message loop -> the long
           "not responding" hang. We keep the page running and never block on its script bugs. */
        IWebBrowser2_put_Silent(v->wb, VARIANT_TRUE);
    }
    hr = IOleObject_QueryInterface(v->obj, &xIID_IOleInPlaceObject, (void **)&v->ipo);
    vlog("QI(IOleInPlaceObject) hr=0x%08X ipo=%p", (unsigned)hr, (void*)v->ipo);
    IOleObject_QueryInterface(v->obj, &xIID_IOleIPActiveObj, (void **)&v->pao);

    if (v->wb) {                                          /* DocumentComplete -> probe (fill / ActiveX / modern page) */
        IConnectionPointContainer *cpc = NULL;
        if (SUCCEEDED(IWebBrowser2_QueryInterface(v->wb, &xIID_ICPContainer, (void **)&cpc)) && cpc) {
            if (SUCCEEDED(IConnectionPointContainer_FindConnectionPoint(cpc, &xDIID_DWebEvents2, &v->cp)) && v->cp)
                IConnectionPoint_Advise(v->cp, (IUnknown *)&v->sink, &v->cookie);
            cpc->lpVtbl->Release(cpc);
        }
    }

    ShowWindow(w, SW_SHOW);
    view_size(v);
    if (GetEnvironmentVariableW(L"IPSCAN_MODERN", NULL, 0)) view_open_modern(v);
    if (!v->engine) {
        if (v->wb) view_navigate(v, url);
        SetTimer(w, 1, 800, NULL);
    }
}
