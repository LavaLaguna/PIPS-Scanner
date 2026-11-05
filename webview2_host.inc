/* WebView2 Evergreen host. The small SDK loader is embedded as a PE resource:
   no browser DLL accompanies the portable executable. Callbacks run on the UI STA. */
typedef HRESULT (STDAPICALLTYPE *WVCreateEnv)(PCWSTR, PCWSTR, ICoreWebView2EnvironmentOptions *, ICoreWebView2CreateCoreWebView2EnvironmentCompletedHandler *);
typedef HRESULT (STDAPICALLTYPE *WVBrowserVersion)(PCWSTR, LPWSTR *);
static HMODULE wv_loader;
static WCHAR wv_loader_file[MAX_PATH];
static WVCreateEnv wv_create_env;
static WVBrowserVersion wv_browser_version;

static int wv_load_embedded(void) {
    if (wv_loader) return 1;
    HRSRC res = FindResourceW(GetModuleHandleW(NULL), MAKEINTRESOURCEW(sizeof(void *) == 8 ? 202 : 201), RT_RCDATA);
    if (!res) return 0;
    HGLOBAL data = LoadResource(GetModuleHandleW(NULL), res);
    DWORD size = SizeofResource(GetModuleHandleW(NULL), res);
    if (!data || !size) return 0;
    WCHAR dir[MAX_PATH]; DWORD n = GetEnvironmentVariableW(L"LOCALAPPDATA", dir, MAX_PATH - 50);
    if (!n || n > MAX_PATH - 50) return 0;
    lstrcatW(dir, L"\\ipscan-webview2"); CreateDirectoryW(dir, NULL);
    wsprintfW(wv_loader_file, L"%s\\loader-%lu.dll", dir, GetCurrentProcessId());
    HANDLE f = CreateFileW(wv_loader_file, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                           FILE_ATTRIBUTE_TEMPORARY, NULL);
    if (f == INVALID_HANDLE_VALUE) return 0;
    DWORD wrote = 0;
    BOOL ok = WriteFile(f, LockResource(data), size, &wrote, NULL);
    CloseHandle(f);
    if (!ok || wrote != size) { DeleteFileW(wv_loader_file); return 0; }
    wv_loader = LoadLibraryW(wv_loader_file);
    if (!wv_loader) { DeleteFileW(wv_loader_file); return 0; }
    wv_create_env = (WVCreateEnv)GetProcAddress(wv_loader, "CreateCoreWebView2EnvironmentWithOptions");
    wv_browser_version = (WVBrowserVersion)GetProcAddress(wv_loader, "GetAvailableCoreWebView2BrowserVersionString");
    if (!wv_create_env || !wv_browser_version) {
        FreeLibrary(wv_loader); wv_loader = NULL;
        DeleteFileW(wv_loader_file); return 0;
    }
    return 1;
}
static void wv_unload_embedded(void) {
    if (wv_loader) { FreeLibrary(wv_loader); wv_loader = NULL; }
    if (wv_loader_file[0]) { DeleteFileW(wv_loader_file); wv_loader_file[0] = 0; }
}
typedef struct {
    const void *vt;
    LONG refs;
    HWND hwnd;
    const GUID *iid;
} WVHandler;
static const GUID wv_iid_src = {0x3c067f9f,0x5388,0x4772,{0x8b,0x48,0x79,0xf7,0xef,0x1a,0xb3,0x7c}};
static const GUID wv_iid_nav = {0xd33a35bf,0x1c49,0x4f98,{0x93,0xab,0x00,0x6e,0x05,0x33,0xfe,0x1c}};
static const GUID wv_iid_popup = {0xd4c185fe,0xc81c,0x4989,{0x97,0xaf,0x2d,0x3f,0xa7,0xab,0x56,0x51}};
static const GUID wv_iid_ctl = {0x6c4819f3,0xc9b7,0x4260,{0x81,0x27,0xc9,0xf5,0xbd,0xe7,0xf6,0x8c}};
static const GUID wv_iid_env = {0x4e8a3389,0xc9d8,0x4bd2,{0xb6,0xb5,0x12,0x4f,0xee,0x6c,0xc1,0x4d}};

static View *wv_alive(HWND h) {
    if (!IsWindow(h)) return NULL;
    View *v = (View *)GetWindowLongPtrW(h, GWLP_USERDATA);
    return v && v->site.hwnd == h ? v : NULL;
}
static HRESULT STDMETHODCALLTYPE wvh_qi(void *self, REFIID iid, void **out) {
    if (!out) return E_POINTER;
    if (!IsEqualGUID(iid, &xIID_IUnknown) && !IsEqualGUID(iid, ((WVHandler *)self)->iid)) {
        *out = NULL; return E_NOINTERFACE;
    }
    *out = self; InterlockedIncrement(&((WVHandler *)self)->refs);
    return S_OK;
}
static ULONG STDMETHODCALLTYPE wvh_add(void *self) {
    return (ULONG)InterlockedIncrement(&((WVHandler *)self)->refs);
}
static ULONG STDMETHODCALLTYPE wvh_rel(void *self) {
    LONG n = InterlockedDecrement(&((WVHandler *)self)->refs);
    if (!n) HeapFree(GetProcessHeap(), 0, self);
    return (ULONG)n;
}
static void *wvh_new(const void *vt, const GUID *iid, HWND h) {
    WVHandler *cb = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof *cb);
    if (cb) { cb->vt = vt; cb->iid = iid; cb->refs = 1; cb->hwnd = h; }
    return cb;
}
static void wv_sync_address(View *v) {
    LPWSTR u = NULL;
    if (v->wv && SUCCEEDED(ICoreWebView2_get_Source(v->wv, &u)) && u) {
        SetWindowTextW(v->addr, u); CoTaskMemFree(u);
    }
}
static HRESULT STDMETHODCALLTYPE wv_source(void *self, ICoreWebView2 *sender,
                                           ICoreWebView2SourceChangedEventArgs *args) {
    (void)sender; (void)args;
    View *v = wv_alive(((WVHandler *)self)->hwnd);
    if (v && v->engine == 1) wv_sync_address(v);
    return S_OK;
}
static const ICoreWebView2SourceChangedEventHandlerVtbl wv_src_vt = {
    (void *)wvh_qi, (void *)wvh_add, (void *)wvh_rel, (void *)wv_source
};

static HRESULT STDMETHODCALLTYPE wv_navdone(void *self, ICoreWebView2 *sender,
                                             ICoreWebView2NavigationCompletedEventArgs *args) {
    (void)sender; (void)args;
    View *v = wv_alive(((WVHandler *)self)->hwnd);
    if (v && v->engine == 1) { wv_sync_address(v); v->wv_fills = 0; SetTimer(v->site.hwnd, 2, 500, NULL); }
    return S_OK;
}
static const ICoreWebView2NavigationCompletedEventHandlerVtbl wv_nav_vt = {
    (void *)wvh_qi, (void *)wvh_add, (void *)wvh_rel, (void *)wv_navdone
};

static HRESULT STDMETHODCALLTYPE wv_popup(void *self, ICoreWebView2 *sender,
                                          ICoreWebView2NewWindowRequestedEventArgs *args) {
    (void)sender;
    View *v = wv_alive(((WVHandler *)self)->hwnd);
    LPWSTR url = NULL;
    if (v && v->wv && SUCCEEDED(args->lpVtbl->get_Uri(args, &url)) && url) {
        /* Reuse the same browser rather than launching a second window. */
        args->lpVtbl->put_Handled(args, TRUE);
        ICoreWebView2_Navigate(v->wv, url);
    }
    if (url) CoTaskMemFree(url);
    return S_OK;
}
static const ICoreWebView2NewWindowRequestedEventHandlerVtbl wv_popup_vt = {
    (void *)wvh_qi, (void *)wvh_add, (void *)wvh_rel, (void *)wv_popup
};

static void wv_listen(View *v) {
    EventRegistrationToken token;
    WVHandler *h = wvh_new(&wv_src_vt, &wv_iid_src, v->site.hwnd);
    if (h) { ICoreWebView2_add_SourceChanged(v->wv, (void *)h, &token); wvh_rel(h); }
    h = wvh_new(&wv_nav_vt, &wv_iid_nav, v->site.hwnd);
    if (h) { ICoreWebView2_add_NavigationCompleted(v->wv, (void *)h, &token); wvh_rel(h); }
    h = wvh_new(&wv_popup_vt, &wv_iid_popup, v->site.hwnd);
    if (h) { ICoreWebView2_add_NewWindowRequested(v->wv, (void *)h, &token); wvh_rel(h); }
}
static HRESULT STDMETHODCALLTYPE wv_controller_ready(void *self, HRESULT hr, ICoreWebView2Controller *ctl) {
    View *v = wv_alive(((WVHandler *)self)->hwnd);
    if (!v || v->engine != 2) return S_OK;
    if (FAILED(hr) || !ctl) { modern_restore_ie(v); vlog("WebView2 controller failed 0x%08X", (unsigned)hr); return S_OK; }
    v->wvctl = ctl; ICoreWebView2Controller_AddRef(ctl);
    if (FAILED(ICoreWebView2Controller_get_CoreWebView2(ctl, &v->wv))) {
        modern_restore_ie(v); return S_OK;
    }
    v->engine = 1;
    modern_size(v);
    wv_listen(v);
    WCHAR u[1024]; GetWindowTextW(v->addr, u, 1024);
    if (u[0]) ICoreWebView2_Navigate(v->wv, u);
    modern_fill(v);
    return S_OK;
}
static const ICoreWebView2CreateCoreWebView2ControllerCompletedHandlerVtbl wv_ctl_vt = {
    (void *)wvh_qi, (void *)wvh_add, (void *)wvh_rel, (void *)wv_controller_ready
};

static HRESULT STDMETHODCALLTYPE wv_environment_ready(void *self, HRESULT hr, ICoreWebView2Environment *env) {
    View *v = wv_alive(((WVHandler *)self)->hwnd);
    if (!v || v->engine != 2) return S_OK;
    if (FAILED(hr) || !env) { modern_restore_ie(v); vlog("WebView2 environment failed 0x%08X", (unsigned)hr); return S_OK; }
    v->wvenv = env; ICoreWebView2Environment_AddRef(env);
    WVHandler *cb = wvh_new(&wv_ctl_vt, &wv_iid_ctl, v->site.hwnd);
    if (cb) {
        hr = ICoreWebView2Environment_CreateCoreWebView2Controller(env, v->site.hwnd, (void *)cb);
        wvh_rel(cb);
    } else hr = E_OUTOFMEMORY;
    if (FAILED(hr)) { modern_restore_ie(v); vlog("WebView2 controller request failed 0x%08X", (unsigned)hr); }
    return S_OK;
}
static const ICoreWebView2CreateCoreWebView2EnvironmentCompletedHandlerVtbl wv_env_vt = {
    (void *)wvh_qi, (void *)wvh_add, (void *)wvh_rel, (void *)wv_environment_ready
};

static void modern_size(View *v) {
    if (!v->wvctl) return;
    RECT rc; GetClientRect(v->site.hwnd, &rc);
    RECT bounds = {0, VS(30), rc.right, rc.bottom - VS(22)};
    ICoreWebView2Controller_put_Bounds(v->wvctl, bounds);
}
static void modern_close(View *v) {
    KillTimer(v->site.hwnd, 2);
    if (v->wvctl) ICoreWebView2Controller_Close(v->wvctl);
    if (v->wv) { ICoreWebView2_Release(v->wv); v->wv = NULL; }
    if (v->wvctl) { ICoreWebView2Controller_Release(v->wvctl); v->wvctl = NULL; }
    if (v->wvenv) { ICoreWebView2Environment_Release(v->wvenv); v->wvenv = NULL; }
}
static void modern_restore_ie(View *v) {
    modern_close(v);
    v->engine = 0;
    if (v->obj) {
        RECT rc; GetClientRect(v->site.hwnd, &rc);
        RECT r = {0, VS(30), rc.right, rc.bottom - VS(22)};
        IOleObject_DoVerb(v->obj, OLEIVERB_INPLACEACTIVATE, NULL, &v->site.cs, 0, v->site.hwnd, &r);
        if (v->ipo) IOleInPlaceObject_SetObjectRects(v->ipo, &r, &r);
    }
    SetWindowTextW(v->site.hwnd, L"Viewer  -  IE / ActiveX (WebView2 unavailable)");
    SetTimer(v->site.hwnd, 1, 800, NULL);
}
static void modern_start(View *v) {
    if (v->engine || !v->site.hwnd) return;
    if (!wv_load_embedded()) { vlog("WebView2 loader failed"); return; }
    LPWSTR vers = NULL;
    HRESULT hr = wv_browser_version(NULL, &vers);
    if (vers) CoTaskMemFree(vers);
    if (FAILED(hr)) {
        vlog("WebView2 Evergreen not installed hr=0x%08X", (unsigned)hr);
        static int prompted;
        if (!prompted++) {
            if (MessageBoxW(v->site.hwnd,
                    L"Modern pages need the Microsoft Edge WebView2 Runtime, which is not installed.\n\n"
                    L"IE/ActiveX will remain available for cameras and NVRs.\n\n"
                    L"Open Microsoft's official WebView2 download page?",
                    L"WebView2 Runtime required", MB_YESNO | MB_ICONINFORMATION) == IDYES)
                ShellExecuteW(v->site.hwnd, L"open",
                    L"https://developer.microsoft.com/en-us/microsoft-edge/webview2/",
                    NULL, NULL, SW_SHOWNORMAL);
        }
        return;
    }
    v->engine = 2;
    /* Use a writable per-user data directory; never write into Program Files. */
    WCHAR path[MAX_PATH]; DWORD n = GetEnvironmentVariableW(L"LOCALAPPDATA", path, MAX_PATH - 32);
    if (!n || n > MAX_PATH - 32) { v->engine = 0; return; }
    lstrcatW(path, L"\\ipscan-webview2");
    WVHandler *cb = wvh_new(&wv_env_vt, &wv_iid_env, v->site.hwnd);
    if (!cb) { v->engine = 0; return; }
    hr = wv_create_env(NULL, path, NULL, (void *)cb);
    wvh_rel(cb);
    if (FAILED(hr)) { v->engine = 0; vlog("WebView2 startup failed hr=0x%08X", (unsigned)hr); }
}

/* Escaped JSON string literals: no credentials are interpolated into executable JS. */
static void wv_js_quote(WCHAR *dst, size_t cap, const WCHAR *src) {
    size_t i = 0; if (cap < 8) return;
    dst[i++] = '"';
    for (; *src && i + 8 < cap; src++) {
        static const WCHAR hex[] = L"0123456789abcdef";
        unsigned c = (unsigned)*src;
        dst[i++] = '\\'; dst[i++] = 'u';
        dst[i++] = hex[(c >> 12) & 15]; dst[i++] = hex[(c >> 8) & 15];
        dst[i++] = hex[(c >> 4) & 15]; dst[i++] = hex[c & 15];
    }
    dst[i++] = '"'; dst[i] = 0;
}
static void modern_fill(View *v) {
    if (!v->wv || (!v->fuser[0] && !v->fpass[0])) return;
    LPWSTR src = NULL;
    if (FAILED(ICoreWebView2_get_Source(v->wv, &src)) || !src) return;
    const WCHAR *host = wcsstr(src, L"://"); host = host ? host + 3 : src;
    int same = _wcsnicmp(host, v->credential_host, lstrlenW(v->credential_host)) == 0;
    WCHAR boundary = host[lstrlenW(v->credential_host)];
    same = same && (boundary == 0 || boundary == ':' || boundary == '/' || boundary == '?' || boundary == '#');
    CoTaskMemFree(src);
    if (!same) return;
    WCHAR u[512], p[512], js[4096];
    wv_js_quote(u, 512, v->fuser); wv_js_quote(p, 512, v->fpass);
    /* Native property setter supports React/Vue forms; dispatch bubbling events. */
    lstrcpyW(js, L"(function(){const U="); lstrcatW(js, u);
    lstrcatW(js, L",P="); lstrcatW(js, p);
    lstrcatW(js, L";function f(d){try{const a=[...d.querySelectorAll('input')];"
        L"const pw=a.find(x=>x.type==='password');let un=a.find(x=>/user|login|account|email/i.test(x.name+' '+x.id+' '+x.placeholder));"
        L"if(!un&&pw)un=a.slice(0,a.indexOf(pw)).reverse().find(x=>x.type==='text'||x.type==='email');"
        L"function set(x,val){if(!x)return;const s=Object.getOwnPropertyDescriptor(HTMLInputElement.prototype,'value').set;"
        L"s.call(x,val);x.dispatchEvent(new Event('input',{bubbles:true}));x.dispatchEvent(new Event('change',{bubbles:true}));}"
        L"set(un,U);set(pw,P);for(const fr of d.querySelectorAll('iframe')){try{f(fr.contentDocument)}catch(e){}}}catch(e){}}f(document)})();");
    ICoreWebView2_ExecuteScript(v->wv, js, NULL);
}
