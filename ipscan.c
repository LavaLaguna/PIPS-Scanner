/*  ipscan - minimal portable network scanner for Windows
 *
 *  Targets (comma separated):  192.168.1.1-254, 10.0.0.0/24, 10.0.0.5-10.0.1.20, 172.16.0.9, nvr01
 *  Detection : ARP (same subnet), ICMP ping, TCP connect to common ports (other subnets)
 *  Names     : reverse DNS, NetBIOS
 *  Vendor    : embedded IEEE registry (MA-L /24, MA-M /28, MA-S /36), deflate-compressed
 *  Type      : guessed from vendor, open ports, HTTP banner/title, SNMP sysDescr, TTL
 *
 *  Builds with the standard C runtime (ships with Windows; no install needed).
 */
#define WIN32_LEAN_AND_MEAN
#define COBJMACROS
#undef _WIN32_WINNT
#undef WINVER
#define _WIN32_WINNT 0x0502          /* keep struct sizes XP/7-compatible */
#define WINVER 0x0502
#ifndef UNICODE
#define UNICODE
#endif
#define _UNICODE
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include <icmpapi.h>
#include <commctrl.h>
#include <commdlg.h>
#include <shellapi.h>
#include <uxtheme.h>
#include <stddef.h>
#include <wincrypt.h>
#include <bcrypt.h>
#include <wincred.h>
#include <wininet.h>
#include <winnetwk.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include "vendor/sqlite/sqlite3.h"
#include "oui.h"

/* VS()/view_font() shims for the embedded viewer, defined after S()/g_font below */
static int VS(int v);
static HFONT view_font(void);
void open_viewer(HWND parent, HINSTANCE hi, const WCHAR *ip, const WCHAR *user, const WCHAR *pass);
int viewer_pretranslate(MSG *m);
static int g_view_standalone;

/* =====================================================================
 *  small helpers
 * ===================================================================== */
static void *xalloc(size_t n) { return HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, n); }
static void *xrealloc(void *p, size_t n) { return p ? HeapReAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, p, n) : xalloc(n); }
static void xfree(void *p) { if (p) HeapFree(GetProcessHeap(), 0, p); }
static void wipe(void *p, size_t n) { volatile BYTE *v = (volatile BYTE *)p; while (n--) *v++ = 0; }

static WCHAR *wchr(WCHAR *s, WCHAR c) { for (; *s; s++) if (*s == c) return s; return NULL; }
static int isdelim(WCHAR c) { return c == ',' || c == ';' || c == ' ' || c == '\t' || c == '\r' || c == '\n'; }
static WCHAR *next_tok(WCHAR **ctx) {
    WCHAR *s = *ctx;
    while (*s && isdelim(*s)) s++;
    if (!*s) return NULL;
    WCHAR *t = s;
    while (*s && !isdelim(*s)) s++;
    if (*s) *s++ = 0;
    *ctx = s; return t;
}
static int wnum(const WCHAR *s, const WCHAR **end) {
    int v = -1;
    for (; *s >= '0' && *s <= '9'; s++) { v = (v < 0 ? 0 : v) * 10 + (*s - '0'); if (v > 99999) v = 99999; }
    *end = s; return v;
}
static char lc(char c) { return (c >= 'A' && c <= 'Z') ? c + 32 : c; }
/* case-insensitive find, needle must be lower case */
static const char *ci_find(const char *h, const char *n) {
    for (; *h; h++) {
        const char *a = h, *b = n;
        while (*b && lc(*a) == *b) a++, b++;
        if (!*b) return h;
    }
    return NULL;
}
static int slen(const char *s) { return (int)strlen(s); }
/* append src (n chars, or until NUL when n<0) to dst of capacity cap, collapsing whitespace */
static void sappend(char *dst, int cap, const char *src, int n) {
    int l = slen(dst);
    for (int i = 0; (n < 0 || i < n) && src[i] && l < cap - 1; i++) {
        char c = src[i];
        if (c == '\r' || c == '\n' || c == '\t') c = ' ';
        if (c == ' ' && (l == 0 || dst[l - 1] == ' ')) continue;
        dst[l++] = c;
    }
    while (l > 0 && dst[l - 1] == ' ') l--;
    dst[l] = 0;
}

/* append s to dst, preceded by sep when dst is not empty */
static void join(char *dst, int cap, const char *sep, const char *s) {
    if (!s || !*s) return;
    int l = slen(dst);
    if (l) for (; *sep && l < cap - 1; sep++) dst[l++] = *sep;
    dst[l] = 0;
    sappend(dst, cap, s, -1);
}

/* =====================================================================
 *  inflate (raw deflate) - after Mark Adler's puff.c
 * ===================================================================== */
typedef struct { const BYTE *in; size_t inlen, inpos; DWORD bitbuf; int bitcnt; BYTE *out; size_t outlen, outpos; } INF;
typedef struct { short count[16]; short symbol[288]; } HUFF;

static int bits(INF *s, int need) {
    DWORD v = s->bitbuf;
    while (s->bitcnt < need) {
        if (s->inpos >= s->inlen) return -1;
        v |= (DWORD)s->in[s->inpos++] << s->bitcnt;
        s->bitcnt += 8;
    }
    s->bitbuf = v >> need; s->bitcnt -= need;
    return (int)(v & ((1UL << need) - 1));
}
static int hdecode(INF *s, const HUFF *h) {
    int code = 0, first = 0, index = 0;
    for (int len = 1; len < 16; len++) {
        int b = bits(s, 1); if (b < 0) return -1;
        code |= b;
        int count = h->count[len];
        if (code - count < first) return h->symbol[index + (code - first)];
        index += count; first += count; first <<= 1; code <<= 1;
    }
    return -1;
}
static void hbuild(HUFF *h, const short *len, int n) {
    short offs[16];
    for (int i = 0; i < 16; i++) h->count[i] = 0;
    for (int i = 0; i < n; i++) h->count[len[i]]++;
    offs[1] = 0;
    for (int i = 1; i < 15; i++) offs[i + 1] = offs[i] + h->count[i];
    for (int i = 0; i < n; i++) if (len[i]) h->symbol[offs[len[i]]++] = (short)i;
}
static int codes(INF *s, const HUFF *lh, const HUFF *dh) {
    static const short lbase[29] = {3,4,5,6,7,8,9,10,11,13,15,17,19,23,27,31,35,43,51,59,67,83,99,115,131,163,195,227,258};
    static const short lext[29] = {0,0,0,0,0,0,0,0,1,1,1,1,2,2,2,2,3,3,3,3,4,4,4,4,5,5,5,5,0};
    static const short dbase[30] = {1,2,3,4,5,7,9,13,17,25,33,49,65,97,129,193,257,385,513,769,1025,1537,2049,3073,4097,6145,8193,12289,16385,24577};
    static const short dext[30] = {0,0,0,0,1,1,2,2,3,3,4,4,5,5,6,6,7,7,8,8,9,9,10,10,11,11,12,12,13,13};
    for (;;) {
        int sym = hdecode(s, lh);
        if (sym < 0) return -1;
        if (sym < 256) { if (s->outpos >= s->outlen) return -1; s->out[s->outpos++] = (BYTE)sym; }
        else if (sym == 256) return 0;
        else {
            sym -= 257; if (sym >= 29) return -1;
            int len = lbase[sym] + bits(s, lext[sym]);
            int ds = hdecode(s, dh); if (ds < 0 || ds >= 30) return -1;
            size_t dist = dbase[ds] + bits(s, dext[ds]);
            if (dist > s->outpos || s->outpos + len > s->outlen) return -1;
            while (len--) { s->out[s->outpos] = s->out[s->outpos - dist]; s->outpos++; }
        }
    }
}
static int inflate_raw(const BYTE *in, size_t inlen, BYTE *out, size_t outlen) {
    static HUFF lh, dh;
    INF s = { in, inlen, 0, 0, 0, out, outlen, 0 };
    short len[320];
    int last;
    do {
        last = bits(&s, 1);
        int type = bits(&s, 2);
        if (type == 0) {
            s.bitbuf = 0; s.bitcnt = 0;
            if (s.inpos + 4 > inlen) return -1;
            unsigned n = s.in[s.inpos] | (s.in[s.inpos + 1] << 8); s.inpos += 4;
            if (s.inpos + n > inlen || s.outpos + n > outlen) return -1;
            while (n--) s.out[s.outpos++] = s.in[s.inpos++];
        } else if (type == 1) {
            int i = 0;
            for (; i < 144; i++) len[i] = 8;
            for (; i < 256; i++) len[i] = 9;
            for (; i < 280; i++) len[i] = 7;
            for (; i < 288; i++) len[i] = 8;
            hbuild(&lh, len, 288);
            for (i = 0; i < 30; i++) len[i] = 5;
            hbuild(&dh, len, 30);
            if (codes(&s, &lh, &dh)) return -1;
        } else if (type == 2) {
            static const BYTE order[19] = {16,17,18,0,8,7,9,6,10,5,11,4,12,3,13,2,14,1,15};
            int nlen = bits(&s, 5) + 257, ndist = bits(&s, 5) + 1, ncode = bits(&s, 4) + 4, i;
            if (nlen > 286 || ndist > 30) return -1;
            for (i = 0; i < 19; i++) len[order[i]] = i < ncode ? (short)bits(&s, 3) : 0;
            hbuild(&lh, len, 19);
            for (i = 0; i < nlen + ndist;) {
                int sym = hdecode(&s, &lh), rep = 0; short v = 0;
                if (sym < 0) return -1;
                if (sym < 16) { len[i++] = (short)sym; continue; }
                if (sym == 16) { if (!i) return -1; v = len[i - 1]; rep = 3 + bits(&s, 2); }
                else if (sym == 17) rep = 3 + bits(&s, 3);
                else rep = 11 + bits(&s, 7);
                if (i + rep > nlen + ndist) return -1;
                while (rep--) len[i++] = v;
            }
            hbuild(&lh, len, nlen);
            hbuild(&dh, len + nlen, ndist);
            if (codes(&s, &lh, &dh)) return -1;
        } else return -1;
    } while (!last);
    return (int)s.outpos;
}

/* =====================================================================
 *  MAC vendor lookup
 * ===================================================================== */
static HWND g_wnd;                         /* forward: the update thread posts here */
#define WM_UPDDONE (WM_APP + 4)
#define WM_SHARE   (WM_APP + 5)
#define WM_PINGMSG (WM_APP + 6)
#define WM_MONPING (WM_APP + 7)
#define WM_PINGDOT (WM_APP + 8)
#define WM_OSDNAME (WM_APP + 9)
static const char **g_vname;
static DWORD *g_k24, *g_k28; static unsigned long long *g_k36;
static DWORD *g_i24, *g_i28, *g_i36;
static int g_n24, g_n28, g_n36;
static char *g_oui_pool;                 /* backing store for the name strings */

static unsigned long long rdvar(const BYTE **p) {
    unsigned long long v = 0; int sh = 0;
    while (**p & 0x80) { v |= (unsigned long long)(**p & 0x7F) << sh; sh += 7; (*p)++; }
    v |= (unsigned long long)**p << sh; (*p)++;
    return v;
}

static void load_embedded_oui(void) {
    BYTE *raw = (BYTE *)xalloc(OUI_RAW + 1);
    if (!raw || inflate_raw(OUI_Z, sizeof OUI_Z, raw, OUI_RAW) != OUI_RAW) return;
    g_oui_pool = (char *)raw;
    const BYTE *p = raw;
    int nn = (int)rdvar(&p);
    g_vname = (const char **)xalloc(nn * sizeof(char *));
    for (int i = 0; i < nn; i++) { g_vname[i] = (const char *)p; while (*p) p++; p++; }
    for (int t = 0; t < 3; t++) {
        int n = (int)rdvar(&p);
        unsigned long long k = 0;
        DWORD *ix = (DWORD *)xalloc(n * sizeof(DWORD));
        void *ks = xalloc(n * (t == 2 ? 8 : 4));
        for (int i = 0; i < n; i++) {
            k += rdvar(&p); ix[i] = (DWORD)rdvar(&p);
            if (t == 2) ((unsigned long long *)ks)[i] = k; else ((DWORD *)ks)[i] = (DWORD)k;
        }
        if (t == 0) { g_k24 = ks; g_i24 = ix; g_n24 = n; }
        else if (t == 1) { g_k28 = ks; g_i28 = ix; g_n28 = n; }
        else { g_k36 = ks; g_i36 = ix; g_n36 = n; }
    }
}

/* ---- parse a Wireshark "manuf" text file into the lookup tables (for Update MAC DB) ---- */
static int hexb(const char *s, const char **end) {
    int v = 0, n = 0;
    while (n < 2 && ((*s >= '0' && *s <= '9') || (*s >= 'a' && *s <= 'f') || (*s >= 'A' && *s <= 'F'))) {
        char c = *s++; v = v * 16 + (c <= '9' ? c - '0' : (c | 32) - 'a' + 10); n++;
    }
    *end = s; return n ? v : -1;
}
static void qsort32(DWORD *k, DWORD *v, int lo, int hi) {
    while (lo < hi) {
        DWORD pk = k[(lo + hi) >> 1];
        int i = lo, j = hi;
        while (i <= j) {
            while (k[i] < pk) i++;
            while (k[j] > pk) j--;
            if (i <= j) { DWORD tk = k[i]; k[i] = k[j]; k[j] = tk; DWORD tv = v[i]; v[i] = v[j]; v[j] = tv; i++; j--; }
        }
        if (j - lo < hi - i) { qsort32(k, v, lo, j); lo = i; } else { qsort32(k, v, i, hi); hi = j; }
    }
}
static void qsort64(unsigned long long *k, DWORD *v, int lo, int hi) {
    while (lo < hi) {
        unsigned long long pk = k[(lo + hi) >> 1];
        int i = lo, j = hi;
        while (i <= j) {
            while (k[i] < pk) i++;
            while (k[j] > pk) j--;
            if (i <= j) { unsigned long long tk = k[i]; k[i] = k[j]; k[j] = tk; DWORD tv = v[i]; v[i] = v[j]; v[j] = tv; i++; j--; }
        }
        if (j - lo < hi - i) { qsort64(k, v, lo, j); lo = i; } else { qsort64(k, v, i, hi); hi = j; }
    }
}

/* returns total entries parsed, or 0 on failure; replaces the live tables on success */
static int parse_manuf(const char *txt, int len) {
    int cap = 4096, n24 = 0, n28 = 0, n36 = 0, pcap = 1 << 20, plen = 0;
    DWORD *k24 = xalloc(cap * 4), *i24 = xalloc(cap * 4), *k28 = xalloc(cap * 4), *i28 = xalloc(cap * 4), *i36 = xalloc(cap * 4);
    unsigned long long *k36 = xalloc(cap * 8);
    char *pool = xalloc(pcap);
    int c24 = cap, c28 = cap, c36 = cap;
    if (!k24 || !i24 || !k28 || !i28 || !i36 || !k36 || !pool) goto fail;
    const char *p = txt, *e = txt + len;
    while (p < e) {
        const char *ln = p;
        while (p < e && *p != '\n') p++;
        const char *le = p; p++;
        if (ln >= le || *ln == '#') continue;
        BYTE b[6]; int nb = 0; const char *q = ln;
        for (; nb < 6; nb++) {
            const char *ne; int v = hexb(q, &ne);
            if (v < 0) break;
            b[nb] = (BYTE)v; q = ne;
            if (*q == ':' || *q == '-') q++;
        }
        if (nb < 3) continue;
        int bits = nb * 8;
        if (*q == '/') { q++; bits = 0; while (*q >= '0' && *q <= '9') bits = bits * 10 + (*q++ - '0'); }
        while (q < le && *q != '\t') q++;              /* to short name */
        if (q < le) q++;
        const char *nm = q, *nme = q;
        const char *t2 = q;                             /* prefer the long (3rd) column */
        while (t2 < le && *t2 != '\t') t2++;
        if (t2 < le) { nm = t2 + 1; nme = le; } else { nme = t2; }
        while (nm < nme && (*nm == ' ' || *nm == '\t')) nm++;
        while (nme > nm && (nme[-1] == ' ' || nme[-1] == '\t' || nme[-1] == '\r')) nme--;
        if (nm >= nme) continue;
        if (plen + 48 > pcap) { pcap *= 2; char *np = xrealloc(pool, pcap); if (!np) goto fail; pool = np; }
        int off = plen, w = 0;
        for (const char *c = nm; c < nme && w < 40; c++) { char ch = *c; if ((unsigned char)ch >= 32) pool[plen++] = ch; w++; }
        pool[plen++] = 0;
        if (bits <= 24) {
            if (n24 >= c24) { c24 *= 2; k24 = xrealloc(k24, c24 * 4); i24 = xrealloc(i24, c24 * 4); if (!k24 || !i24) goto fail; }
            k24[n24] = ((DWORD)b[0] << 16) | ((DWORD)b[1] << 8) | b[2]; i24[n24++] = off;
        } else if (bits <= 28) {
            if (n28 >= c28) { c28 *= 2; k28 = xrealloc(k28, c28 * 4); i28 = xrealloc(i28, c28 * 4); if (!k28 || !i28) goto fail; }
            k28[n28] = ((DWORD)b[0] << 24) | ((DWORD)b[1] << 16) | ((DWORD)b[2] << 8) | (b[3] & 0xF0); i28[n28++] = off;
        } else {
            if (n36 >= c36) { c36 *= 2; k36 = xrealloc(k36, c36 * 8); i36 = xrealloc(i36, c36 * 4); if (!k36 || !i36) goto fail; }
            k36[n36] = ((unsigned long long)b[0] << 32) | ((unsigned long long)b[1] << 24) |
                       ((DWORD)b[2] << 16) | ((DWORD)b[3] << 8) | (b[4] & 0xF0); i36[n36++] = off;
        }
    }
    if (n24 + n28 + n36 < 1000) goto fail;              /* sanity: not a real manuf file */
    if (n24) qsort32(k24, i24, 0, n24 - 1);
    if (n28) qsort32(k28, i28, 0, n28 - 1);
    if (n36) qsort64(k36, i36, 0, n36 - 1);
    int total = n24 + n28 + n36;
    const char **vname = xalloc(total * sizeof(char *));
    if (!vname) goto fail;
    /* offsets are absolute into pool; store pool base and convert offset->index via a shim */
    for (int i = 0; i < n24; i++) vname[i] = pool + i24[i], i24[i] = i;
    for (int i = 0; i < n28; i++) vname[n24 + i] = pool + i28[i], i28[i] = n24 + i;
    for (int i = 0; i < n36; i++) vname[n24 + n28 + i] = pool + i36[i], i36[i] = n24 + n28 + i;
    /* swap in */
    xfree(g_k24); xfree(g_i24); xfree(g_k28); xfree(g_i28); xfree(g_k36); xfree(g_i36);
    xfree((void *)g_vname); xfree(g_oui_pool);
    g_k24 = k24; g_i24 = i24; g_n24 = n24;
    g_k28 = k28; g_i28 = i28; g_n28 = n28;
    g_k36 = k36; g_i36 = i36; g_n36 = n36;
    g_vname = vname; g_oui_pool = pool;
    return total;
fail:
    xfree(k24); xfree(i24); xfree(k28); xfree(i28); xfree(k36); xfree(i36); xfree(pool);
    return 0;
}

/* ipscan-manuf.txt next to the exe, else in %APPDATA% */
static void manuf_path(WCHAR *out, int appdata) {
    if (appdata) { ExpandEnvironmentStringsW(L"%APPDATA%\\ipscan-manuf.txt", out, MAX_PATH); return; }
    DWORD n = GetModuleFileNameW(NULL, out, MAX_PATH - 20);
    while (n && out[n - 1] != '\\') n--;
    lstrcpyW(out + n, L"ipscan-manuf.txt");
}
static char *read_file(const WCHAR *path, int *len) {
    HANDLE f = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (f == INVALID_HANDLE_VALUE) return NULL;
    DWORD sz = GetFileSize(f, NULL);
    char *b = (sz && sz < 64u * 1024 * 1024) ? (char *)xalloc(sz + 1) : NULL;
    DWORD got = 0;
    if (b) ReadFile(f, b, sz, &got, NULL);
    CloseHandle(f);
    if (b) { b[got] = 0; *len = (int)got; }
    return b;
}
static int g_oui_count;                 /* entries currently loaded (0 = embedded) */
static void load_oui(void) {
    for (int ad = 0; ad < 2; ad++) {
        WCHAR path[MAX_PATH]; manuf_path(path, ad);
        int len; char *t = read_file(path, &len);
        if (t) { int n = parse_manuf(t, len); xfree(t); if (n) { g_oui_count = n; return; } }
    }
    load_embedded_oui();
}

static const WCHAR MANUF_URL[] = L"https://www.wireshark.org/download/automated/data/manuf";
/* download the current manuf list over HTTPS (WinINet uses the system proxy) */
static char *http_download(const WCHAR *url, int *len) {
    HINTERNET in = InternetOpenW(L"ipscan", INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
    if (!in) return NULL;
    DWORD to = 20000;
    InternetSetOptionW(in, INTERNET_OPTION_CONNECT_TIMEOUT, &to, sizeof to);
    InternetSetOptionW(in, INTERNET_OPTION_RECEIVE_TIMEOUT, &to, sizeof to);
    HINTERNET u = InternetOpenUrlW(in, url, NULL, 0,
                                   INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_UI | INTERNET_FLAG_SECURE, 0);
    char *buf = NULL; int cap = 1 << 21, n = 0;
    if (u) {
        buf = (char *)xalloc(cap);
        DWORD got;
        while (buf && InternetReadFile(u, buf + n, cap - 1 - n, &got) && got) {
            n += got;
            if (n + 65536 > cap) { cap *= 2; char *nb = xrealloc(buf, cap); if (!nb) { xfree(buf); buf = NULL; break; } buf = nb; }
        }
        InternetCloseHandle(u);
    }
    InternetCloseHandle(in);
    if (buf) { buf[n] = 0; *len = n; }
    return buf;
}

static DWORD WINAPI update_thread(LPVOID unused) {
    (void)unused;
    int len = 0;
    char *t = http_download(MANUF_URL, &len);
    if (!t || len < 100000) { xfree(t); PostMessageW(g_wnd, WM_UPDDONE, 0, 0); return 0; }
    /* save a copy first, then parse (parse consumes/keeps the buffer as the name pool) */
    for (int ad = 0; ad < 2; ad++) {
        WCHAR path[MAX_PATH]; manuf_path(path, ad);
        HANDLE f = CreateFileW(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
        if (f != INVALID_HANDLE_VALUE) { DWORD w; WriteFile(f, t, len, &w, NULL); CloseHandle(f); break; }
    }
    int n = parse_manuf(t, len);
    xfree(t);
    if (n) g_oui_count = n;
    PostMessageW(g_wnd, WM_UPDDONE, (WPARAM)n, 0);
    return 0;
}

static int bsearch32(const DWORD *k, int n, DWORD key) {   /* MAC-maker binary search */
    int lo = 0, hi = n - 1;
    while (lo <= hi) { int m = (lo + hi) >> 1; if (k[m] == key) return m; if (k[m] < key) lo = m + 1; else hi = m - 1; }
    return -1;
}

static const char *vendor_of(const BYTE *m) {
    if (!g_vname) return "";
    unsigned long long k36 = ((unsigned long long)m[0] << 32) | ((unsigned long long)m[1] << 24) |
                             ((DWORD)m[2] << 16) | ((DWORD)m[3] << 8) | (m[4] & 0xF0);
    int lo = 0, hi = g_n36 - 1;
    while (lo <= hi) {
        int mid = (lo + hi) >> 1;
        if (g_k36[mid] == k36) return g_vname[g_i36[mid]];
        if (g_k36[mid] < k36) lo = mid + 1; else hi = mid - 1;
    }
    int i = bsearch32(g_k28, g_n28, ((DWORD)m[0] << 24) | ((DWORD)m[1] << 16) | ((DWORD)m[2] << 8) | (m[3] & 0xF0));
    if (i >= 0) return g_vname[g_i28[i]];
    i = bsearch32(g_k24, g_n24, ((DWORD)m[0] << 16) | ((DWORD)m[1] << 8) | m[2]);
    if (i >= 0) return g_vname[g_i24[i]];
    if (m[0] & 2) return "(private / random MAC)";
    return "";
}

/* =====================================================================
 *  scanning
 * ===================================================================== */
#define MAX_HOSTS   65536
#define MAX_THREADS 128
#define PING_MS     700
#define TCP_MS      700
#define UDP_MS      600
#define HTTP_MS     1000

static const u_short PORTS[] = { 21, 22, 23, 53, 80, 88, 135, 139, 389, 443, 445, 515, 554, 631,
                                 3389, 5000, 8000, 8080, 8291, 8443, 9100, 34567, 37777 };
#define NPORTS (int)(sizeof PORTS / sizeof PORTS[0])
static DWORD pbit(u_short port) { for (int i = 0; i < NPORTS; i++) if (PORTS[i] == port) return 1u << i; return 0; }

typedef struct {
    DWORD ip; int alive, rtt, ttl; DWORD ports;
    WCHAR ips[16], name[64], mac[18], vendor[32], desc[128], type[24], auth[40], events[160], autotype[24], autodev[96], ping[10], monitor[16], portsw[64], info[240];
    int confident;
} RES;

#define WM_RESULT (WM_APP + 1)
#define WM_DONE   (WM_APP + 2)
#define WM_ERRMSG (WM_APP + 3)

static DWORD *g_ips;
static volatile LONG g_total, g_next, g_done, g_alive, g_stop, g_running;
static struct { DWORD ip, mask; BYTE mac[6]; } g_if[32];
static int g_nif;

static void ip2w(DWORD ip, WCHAR *o) {
    wsprintfW(o, L"%u.%u.%u.%u", ip >> 24, (ip >> 16) & 255, (ip >> 8) & 255, ip & 255);
}

static int parse_ip(const WCHAR *s, DWORD *out) {
    DWORD v = 0; int parts = 0;
    while (parts < 4) {
        if (*s < '0' || *s > '9') return 0;
        DWORD o = 0; int d = 0;
        while (*s >= '0' && *s <= '9') { o = o * 10 + (*s++ - '0'); if (++d > 3) return 0; }
        if (o > 255) return 0;
        v = (v << 8) | o; parts++;
        if (parts < 4) { if (*s != '.') return 0; s++; }
    }
    if (*s) return 0;
    *out = v; return 1;
}

static void load_interfaces(void) {
    ULONG len = 0; g_nif = 0;
    if (GetAdaptersInfo(NULL, &len) != ERROR_BUFFER_OVERFLOW) return;
    IP_ADAPTER_INFO *ai = (IP_ADAPTER_INFO *)xalloc(len), *a;
    if (GetAdaptersInfo(ai, &len) == NO_ERROR)
        for (a = ai; a && g_nif < 32; a = a->Next)
            for (IP_ADDR_STRING *s = &a->IpAddressList; s && g_nif < 32; s = s->Next) {
                DWORD ip = ntohl(inet_addr(s->IpAddress.String));
                DWORD mk = ntohl(inet_addr(s->IpMask.String));
                if (!ip || ip == 0xFFFFFFFF) continue;
                g_if[g_nif].ip = ip; g_if[g_nif].mask = mk;
                memcpy(g_if[g_nif].mac, a->Address, 6);
                g_nif++;
            }
    xfree(ai);
}

static int on_link(DWORD ip) {
    for (int i = 0; i < g_nif; i++)
        if (g_if[i].mask && (ip & g_if[i].mask) == (g_if[i].ip & g_if[i].mask)) return 1;
    return 0;
}

/* connect to all PORTS at once; returns bitmask of open ports, *seen=1 if anything answered */
static DWORD port_scan(DWORD nip, int *seen) {
    SOCKET s[NPORTS]; DWORD open = 0;
    for (int i = 0; i < NPORTS; i++) {
        s[i] = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (s[i] == INVALID_SOCKET) continue;
        u_long nb = 1; ioctlsocket(s[i], FIONBIO, &nb);
        struct sockaddr_in sa = {0};
        sa.sin_family = AF_INET; sa.sin_port = htons(PORTS[i]); sa.sin_addr.s_addr = nip;
        if (connect(s[i], (struct sockaddr *)&sa, sizeof sa) == SOCKET_ERROR && WSAGetLastError() != WSAEWOULDBLOCK) {
            closesocket(s[i]); s[i] = INVALID_SOCKET;     /* e.g. network unreachable: says nothing about the host */
        }
    }
    DWORD t0 = GetTickCount();
    for (;;) {
        fd_set wf, ef; FD_ZERO(&wf); FD_ZERO(&ef); int pending = 0;
        for (int i = 0; i < NPORTS; i++) if (s[i] != INVALID_SOCKET) { FD_SET(s[i], &wf); FD_SET(s[i], &ef); pending++; }
        int left = TCP_MS - (int)(GetTickCount() - t0);
        if (!pending || left <= 0) break;
        struct timeval tv = { 0, left * 1000 };
        if (select(0, NULL, &wf, &ef, &tv) <= 0) break;
        for (int i = 0; i < NPORTS; i++) {
            if (s[i] == INVALID_SOCKET) continue;
            if (!FD_ISSET(s[i], &wf) && !FD_ISSET(s[i], &ef)) continue;
            int err = 0, len = sizeof err;
            getsockopt(s[i], SOL_SOCKET, SO_ERROR, (char *)&err, &len);
            if (err == 0 && FD_ISSET(s[i], &wf)) { open |= 1u << i; *seen = 1; }   /* port open */
            else if (err == WSAECONNREFUSED) *seen = 1;          /* RST from the host itself -> host is up */
            /* WSAENETUNREACH / WSAEHOSTUNREACH / WSAETIMEDOUT etc. -> no evidence the host exists */
            closesocket(s[i]); s[i] = INVALID_SOCKET;
        }
    }
    for (int i = 0; i < NPORTS; i++) if (s[i] != INVALID_SOCKET) closesocket(s[i]);
    return open;
}

/* ---------- debug log (hold Shift while clicking Scan) ---------- */
static volatile LONG g_debug;
static char *g_log; static int g_loglen, g_logcap;
static CRITICAL_SECTION g_cs;
static void log_add(const char *s) {
    EnterCriticalSection(&g_cs);
    int n = slen(s);
    if (g_loglen + n + 1 > g_logcap) {
        int nc = (g_logcap ? g_logcap * 2 : 65536); while (nc < g_loglen + n + 1) nc *= 2;
        char *p = (char *)xrealloc(g_log, nc);
        if (p) { g_log = p; g_logcap = nc; }
    }
    if (g_loglen + n + 1 <= g_logcap) { memcpy(g_log + g_loglen, s, n + 1); g_loglen += n; }
    LeaveCriticalSection(&g_cs);
}
static void cat(char *dst, int cap, const char *a) {          /* plain append, keeps newlines */
    int l = slen(dst);
    while (*a && l < cap - 1) dst[l++] = *a++;
    dst[l] = 0;
}

/* ---------- WS-Discovery (ONVIF cameras, WSD printers, Windows PCs) ---------- */
static const char WSD_PROBE[] =
    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
    "<e:Envelope xmlns:e=\"http://www.w3.org/2003/05/soap-envelope\" "
    "xmlns:w=\"http://schemas.xmlsoap.org/ws/2004/08/addressing\" "
    "xmlns:d=\"http://schemas.xmlsoap.org/ws/2005/04/discovery\"><e:Header>"
    "<w:MessageID>uuid:6f3c1a52-8b1d-4e2a-9c47-1b2e3f4a5d6e</w:MessageID>"
    "<w:To e:mustUnderstand=\"true\">urn:schemas-xmlsoap-org:ws:2005:04:discovery</w:To>"
    "<w:Action e:mustUnderstand=\"true\">http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</w:Action>"
    "</e:Header><e:Body><d:Probe/></e:Body></e:Envelope>";

/* copy the text of the first <prefix:tag>...</ element */
static void xml_text(const char *x, const char *tag, char *out, int cap) {
    const char *p = x;
    out[0] = 0;
    while ((p = ci_find(p, tag)) != NULL) {
        if (p > x && (p[-1] == '<' || p[-1] == ':')) {
            const char *q = p + slen(tag);
            if (*q == '>') { q++; int n = 0; while (q[n] && q[n] != '<') n++; sappend(out, cap, q, n); return; }
        }
        p++;
    }
}

/* Everything vendor discovery protocols told us about one host */
typedef struct {
    char scopes[600], xaddr[200], types[200];   /* WS-Discovery (ONVIF, WSD printers, Windows) */
    char maker[40], model[64], kind[8], fw[48];  /* TVT / Hikvision SADP / Dahua / XiongMai search */
    char location[160], server[80], friendly[64];  /* SSDP (UPnP) */
    int vendor;                                  /* maker/model came from a vendor search protocol */
} WSDI;

static void setf(char *dst, int cap, const char *src) { if (!dst[0] && src[0]) sappend(dst, cap, src, -1); }

/* "key": "value" or "key": number, key given in lower case with quotes */
static void json_val(const char *s, const char *key, char *out, int cap) {
    out[0] = 0;
    const char *p = ci_find(s, key);
    if (!p) return;
    p += slen(key);
    while (*p == ' ' || *p == ':') p++;
    int q = *p == '"'; if (q) p++;
    int n = 0;
    while (p[n] && (q ? p[n] != '"' : (p[n] != ',' && p[n] != '}' && p[n] != ' '))) n++;
    sappend(out, cap, p, n);
}

static const char *const NVR_KW[] = { "nvr", "dvr", "xvr", "hvr", "nvs", "recorder", "ds-76", "ds-77", "ds-78",
                                      "ds-86", "ds-90", "ds-96", "tc-r", "td-3", "n9000", 0 };
static const char *const CAM_KW[] = { "ipc", "ipcam", "camera", "nvt", "td-9", "td-7", "td-5", "tc-c", "tc-nc",
                                      "ds-2cd", "ds-2de", "ds-2df", 0 };
static int any_kw(const char *t, const char *const *kw) {
    if (!*t) return 0;
    for (int i = 0; kw[i]; i++) if (ci_find(t, kw[i])) return 1;
    return 0;
}
static void kind_from(char *kind, const char *text) {
    if (kind[0]) return;
    if (any_kw(text, CAM_KW)) lstrcpyA(kind, "IPC");
    else if (any_kw(text, NVR_KW)) lstrcpyA(kind, "NVR");
}

static void wsd_parse(const char *xml, WSDI *w) {
    char tmp[700];
    xml_text(xml, "scopes", tmp, sizeof tmp);
    int n = 0;                                      /* URL-decode %20 etc */
    for (const char *p = tmp; *p && n < (int)sizeof w->scopes - 1; p++) {
        if (*p == '%' && p[1] && p[2]) {
            int v = 0;
            for (int k = 1; k <= 2; k++) { char c = lc(p[k]); v = v * 16 + (c >= 'a' ? c - 'a' + 10 : c - '0'); }
            w->scopes[n++] = (char)v; p += 2;
        } else w->scopes[n++] = *p;
    }
    w->scopes[n] = 0;
    xml_text(xml, "xaddrs", w->xaddr, sizeof w->xaddr);
    xml_text(xml, "types", w->types, sizeof w->types);
}

/* one reply from any discovery protocol */
static void disc_parse(const BYTE *b, int n, WSDI *w) {
    const char *s = (const char *)b;
    char t[96];
    if (n > 32 && b[0] == 0x20 && b[4] == 'D' && b[5] == 'H' && b[6] == 'I' && b[7] == 'P') {     /* Dahua */
        s += 32;
        json_val(s, "\"vendor\"", t, sizeof t);      w->vendor = 1; w->maker[0] = 0; sappend(w->maker, sizeof w->maker, t[0] ? t : "Dahua", -1);
        json_val(s, "\"devicetype\"", t, sizeof t);  setf(w->model, sizeof w->model, t);
        json_val(s, "\"version\"", t, sizeof t);     setf(w->fw, sizeof w->fw, t);
        json_val(s, "\"deviceclass\"", t, sizeof t); kind_from(w->kind, t);
        kind_from(w->kind, w->model);
        return;
    }
    if (n > 20 && b[0] == 0xFF && b[1] == 0x01) {                                                  /* XiongMai */
        s += 20;
        if (!ci_find(s, "netcommon")) return;
        w->vendor = 1; w->maker[0] = 0; sappend(w->maker, sizeof w->maker, "XiongMai", -1);
        json_val(s, "\"hostname\"", t, sizeof t);
        if (!ci_find(t, "localhost")) setf(w->model, sizeof w->model, t);
        json_val(s, "\"channelnum\"", t, sizeof t);
        if (!w->kind[0] && t[0]) lstrcpyA(w->kind, (t[0] == '1' && !t[1]) || t[0] == '0' ? "IPC" : "DVR");
        return;
    }
    if (ci_find(s, "<multicastsearchresult")) {                                                   /* TVT */
        w->vendor = 1; w->maker[0] = 0; sappend(w->maker, sizeof w->maker, "TVT", -1);
        xml_text(s, "productmodel", t, sizeof t);    setf(w->model, sizeof w->model, t);
        xml_text(s, "softwarever", t, sizeof t);     setf(w->fw, sizeof w->fw, t);
        xml_text(s, "productseries", t, sizeof t);
        if (ci_find(t, "ipc")) kind_from(w->kind, "ipc");
        else if (ci_find(t, "nvr") || ci_find(t, "dvr") || ci_find(t, "n9000")) kind_from(w->kind, "nvr");
        kind_from(w->kind, w->model);
        return;
    }
    if (ci_find(s, "<probematch") && ci_find(s, "devicedescription")) {                          /* Hikvision SADP */
        w->vendor = 1; w->maker[0] = 0; sappend(w->maker, sizeof w->maker, "Hikvision", -1);
        xml_text(s, "devicedescription", t, sizeof t); setf(w->model, sizeof w->model, t);
        xml_text(s, "softwareversion", t, sizeof t);   setf(w->fw, sizeof w->fw, t);
        kind_from(w->kind, w->model);
        return;
    }
    if (ci_find(s, "probematches")) { wsd_parse(s, w); return; }                                  /* WS-Discovery */
    if (n > 12 && (ci_find(s, "http/1.1 200") == s || ci_find(s, "notify * ") == s)) {          /* SSDP */
        const char *p;
        if (!w->location[0] && (p = ci_find(s, "\nlocation:")) != NULL) {
            p += 10; while (*p == ' ') p++;
            int k = 0; while (p[k] && p[k] != '\r' && p[k] != '\n') k++;
            sappend(w->location, sizeof w->location, p, k);
        }
        if (!w->server[0] && (p = ci_find(s, "\nserver:")) != NULL) {
            p += 8; int k = 0; while (p[k] && p[k] != '\r' && p[k] != '\n') k++;
            sappend(w->server, sizeof w->server, p, k);
        }
        if (!w->maker[0]) {
            if (ci_find(s, "tiandy")) sappend(w->maker, sizeof w->maker, "Tiandy", -1);
            else if (ci_find(s, "hikvision")) sappend(w->maker, sizeof w->maker, "Hikvision", -1);
            else if (ci_find(s, "dahua")) sappend(w->maker, sizeof w->maker, "Dahua", -1);
        }
    }
}

static int wsd_any(const WSDI *w) { return w->types[0] || w->scopes[0] || w->xaddr[0]; }
static int wsd_onvif(const WSDI *w) {
    return ci_find(w->types, "networkvideo") || ci_find(w->scopes, "onvif://") || ci_find(w->xaddr, "/onvif/");
}

typedef struct { DWORD nip; WSDI w; } WSD;
static WSD *g_wsd; static int g_nwsd;
static volatile LONG g_wsd_done;
static DWORD g_scan_t0;

static void wsd_store(DWORD nip, const BYTE *b, int n) {
    EnterCriticalSection(&g_cs);
    int i = 0;
    while (i < g_nwsd && g_wsd[i].nip != nip) i++;
    if (i == g_nwsd && g_nwsd < 2048) { memset(&g_wsd[i], 0, sizeof g_wsd[i]); g_wsd[i].nip = nip; g_nwsd++; }
    if (i < g_nwsd) disc_parse(b, n, &g_wsd[i].w);
    LeaveCriticalSection(&g_cs);
}
static void wsd_find(DWORD nip, WSDI *w) {
    EnterCriticalSection(&g_cs);
    for (int i = 0; i < g_nwsd; i++) if (g_wsd[i].nip == nip) { *w = g_wsd[i].w; break; }
    LeaveCriticalSection(&g_cs);
}

/* probes sent once per scan */
static const char SSDP_ALL[] = "M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 2\r\nST: ssdp:all\r\n\r\n";
static const char SSDP_TVT[] = "M-SEARCH * HTTP/1.1\r\nHOST:239.255.255.250:1900\r\nMan:\"ssdp:discover\"\r\n"
                               "ST:urn:schemas-upnp-org:service:EmbeddedNetDeviceControl:1\r\nMX:2\r\n\r\n";
static const char SADP_PROBE[] = "<?xml version=\"1.0\" encoding=\"utf-8\"?><Probe><Uuid>13A888A9-F1B1-4020-AE9F-05607682D23B</Uuid>"
                                 "<Types>inquiry</Types></Probe>";
static int dhip_probe(BYTE *p) {
    static const char js[] = "{\"method\":\"DHDiscover.search\",\"params\":{\"mac\":\"\",\"uni\":1}}\n";
    int l = sizeof js - 1;
    memset(p, 0, 32);
    p[0] = 0x20; p[4] = 'D'; p[5] = 'H'; p[6] = 'I'; p[7] = 'P';
    p[16] = (BYTE)l; p[24] = (BYTE)l;
    memcpy(p + 32, js, l);
    return 32 + l;
}
static const BYTE XM_PROBE[20] = { 0xFF, 0x01, 0, 0, 0,0,0,0, 0,0,0,0, 0, 0, 0xFA, 0x05, 0,0,0,0 };

static void send_to(SOCKET s, DWORD nip, u_short port, const void *buf, int len) {
    struct sockaddr_in to = {0};
    to.sin_family = AF_INET; to.sin_port = htons(port); to.sin_addr.s_addr = nip;
    sendto(s, (const char *)buf, len, 0, (struct sockaddr *)&to, sizeof to);
}

/* multicast/broadcast discovery on every local interface, answers collected for 2.5 s */
static DWORD WINAPI wsd_listener(LPVOID p) {
    (void)p;
    SOCKET s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    SOCKET x = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);      /* XiongMai answers to port 34569 */
    BYTE *b = (BYTE *)xalloc(32768), dh[128];
    int dl = dhip_probe(dh);
    if (s != INVALID_SOCKET && b) {
        BOOL on = TRUE;
        struct sockaddr_in me = {0}; me.sin_family = AF_INET;
        bind(s, (struct sockaddr *)&me, sizeof me);
        setsockopt(s, SOL_SOCKET, SO_BROADCAST, (char *)&on, sizeof on);
        if (x != INVALID_SOCKET) {
            setsockopt(x, SOL_SOCKET, SO_REUSEADDR, (char *)&on, sizeof on);
            setsockopt(x, SOL_SOCKET, SO_BROADCAST, (char *)&on, sizeof on);
            me.sin_port = htons(34569);
            if (bind(x, (struct sockaddr *)&me, sizeof me) != 0) { closesocket(x); x = INVALID_SOCKET; }
        }
        int ttl = 2; setsockopt(s, IPPROTO_IP, IP_MULTICAST_TTL, (char *)&ttl, sizeof ttl);
        DWORD mc = inet_addr("239.255.255.250");
        for (int k = 0; k < 2; k++)
            for (int i = 0; i < g_nif; i++) {
                struct in_addr ifa; ifa.s_addr = htonl(g_if[i].ip);
                setsockopt(s, IPPROTO_IP, IP_MULTICAST_IF, (char *)&ifa, sizeof ifa);
                DWORD bc = htonl(g_if[i].ip | ~g_if[i].mask);
                send_to(s, mc, 3702, WSD_PROBE, sizeof WSD_PROBE - 1);
                send_to(s, mc, 1900, SSDP_ALL, sizeof SSDP_ALL - 1);
                send_to(s, mc, 1900, SSDP_TVT, sizeof SSDP_TVT - 1);
                send_to(s, mc, 37020, SADP_PROBE, sizeof SADP_PROBE - 1);
                send_to(s, bc, 37810, dh, dl);
                if (x != INVALID_SOCKET) send_to(x, bc, 34569, XM_PROBE, 20);
            }
        DWORD t0 = GetTickCount();
        for (;;) {
            int left = 1500 - (int)(GetTickCount() - t0);
            if (left <= 0 || g_stop) break;
            fd_set rf; FD_ZERO(&rf); FD_SET(s, &rf);
            if (x != INVALID_SOCKET) FD_SET(x, &rf);
            struct timeval tv = { 0, left * 1000 };
            if (select(0, &rf, NULL, NULL, &tv) <= 0) break;
            SOCKET r = FD_ISSET(s, &rf) ? s : x;
            struct sockaddr_in from; int fl = sizeof from;
            int n = recvfrom(r, (char *)b, 32767, 0, (struct sockaddr *)&from, &fl);
            if (n <= 0) continue;
            b[n] = 0;
            int mine = 0;                                /* our own broadcasts come back on x */
            for (int i = 0; i < g_nif; i++) if (htonl(g_if[i].ip) == from.sin_addr.s_addr) mine = 1;
            if (!mine) wsd_store(from.sin_addr.s_addr, b, n);
        }
    }
    if (s != INVALID_SOCKET) closesocket(s);
    if (x != INVALID_SOCKET) closesocket(x);
    xfree(b);
    InterlockedExchange(&g_wsd_done, 1);
    return 0;
}

/* ---------- DNS name decoding (for mDNS replies) ---------- */
static void dns_name(const BYTE *b, int n, int p, char *out, int cap) {
    int o = 0, jumps = 0;
    while (p < n && jumps < 16) {
        int l = b[p];
        if (!l) break;
        if ((l & 0xC0) == 0xC0) { if (p + 1 >= n) break; p = ((l & 0x3F) << 8) | b[p + 1]; jumps++; continue; }
        p++;
        if (o && o < cap - 1) out[o++] = '.';
        for (int k = 0; k < l && p < n && o < cap - 1; k++) out[o++] = (char)b[p++];
    }
    out[o] = 0;
}
static int dns_skip(const BYTE *b, int n, int p) {
    while (p < n) {
        int l = b[p];
        if (!l) return p + 1;
        if ((l & 0xC0) == 0xC0) return p + 2;
        p += l + 1;
    }
    return n;
}

typedef struct {
    char nb[16]; BYTE nbmac[6];
    char descr[96];          /* SNMP sysDescr */
    char mdns[64];           /* mDNS reverse name */
    WSDI w;
} UDPI;

/* NetBIOS node status + SNMPv1 sysDescr + mDNS reverse PTR + unicast WS-Discovery,
   all sent at once, unanswered ones re-sent once, answers collected for UDP_MS */
static void udp_info(SOCKET us, DWORD nip, UDPI *u) {
    BYTE nb[50] = { 0x1A, 0x2B, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0x20, 'C', 'K' };
    memset(nb + 15, 'A', 30); nb[45] = 0; nb[46] = 0; nb[47] = 0x21; nb[48] = 0; nb[49] = 1;
    static const BYTE snmp[43] = { 0x30,0x29,0x02,0x01,0x00,0x04,0x06,'p','u','b','l','i','c',0xA0,0x1C,
        0x02,0x04,0x49,0x50,0x53,0x43,0x02,0x01,0x00,0x02,0x01,0x00,0x30,0x0E,0x30,0x0C,
        0x06,0x08,0x2B,0x06,0x01,0x02,0x01,0x01,0x01,0x00,0x05,0x00 };
    BYTE md[64] = { 0x49, 0x50, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0 };
    int ml = 12;
    {   /* d.c.b.a.in-addr.arpa PTR, QU bit */
        const BYTE *a = (const BYTE *)&nip;
        for (int i = 3; i >= 0; i--) {
            char t[4]; int l = wsprintfA(t, "%u", a[i]);
            md[ml++] = (BYTE)l; memcpy(md + ml, t, l); ml += l;
        }
        static const BYTE tail[] = { 7,'i','n','-','a','d','d','r',4,'a','r','p','a',0, 0,12, 0x80,1 };
        memcpy(md + ml, tail, sizeof tail); ml += sizeof tail;
    }
    int want_wsd = !wsd_any(&u->w);
    int got_nb = 0, got_snmp = 0, got_md = 0, got_wsd = !want_wsd;
    int got_ssdp = u->w.maker[0] || u->w.location[0];
    struct sockaddr_in sa = {0};
    sa.sin_family = AF_INET; sa.sin_addr.s_addr = nip;
    BYTE b[8192];
    DWORD t0 = GetTickCount();
    for (int round = 0;; round++) {
        if (round == 0 || round == 1) {                 /* initial send, then one re-send of the missing ones */
            if (!got_nb)   { sa.sin_port = htons(137);  sendto(us, (const char *)nb, 50, 0, (struct sockaddr *)&sa, sizeof sa); }
            if (!got_snmp) { sa.sin_port = htons(161);  sendto(us, (const char *)snmp, 43, 0, (struct sockaddr *)&sa, sizeof sa); }
            if (!got_md)   { sa.sin_port = htons(5353); sendto(us, (const char *)md, ml, 0, (struct sockaddr *)&sa, sizeof sa); }
            if (!got_wsd)  { sa.sin_port = htons(3702); sendto(us, WSD_PROBE, sizeof WSD_PROBE - 1, 0, (struct sockaddr *)&sa, sizeof sa); }
            if (!got_ssdp) {
                sa.sin_port = htons(1900);
                sendto(us, SSDP_TVT, sizeof SSDP_TVT - 1, 0, (struct sockaddr *)&sa, sizeof sa);
                sendto(us, SSDP_ALL, sizeof SSDP_ALL - 1, 0, (struct sockaddr *)&sa, sizeof sa);
            }
        }
        for (;;) {
            if (got_nb && got_snmp && got_md && got_wsd && got_ssdp) return;
            int left = (round == 0 ? UDP_MS / 2 : UDP_MS) - (int)(GetTickCount() - t0);
            if (left <= 0) break;
            fd_set rf; FD_ZERO(&rf); FD_SET(us, &rf);
            struct timeval tv = { 0, left * 1000 };
            if (select(0, &rf, NULL, NULL, &tv) <= 0) break;
        struct sockaddr_in from; int fl = sizeof from;
        int n = recvfrom(us, (char *)b, sizeof b - 1, 0, (struct sockaddr *)&from, &fl);
        if (n <= 0 || from.sin_addr.s_addr != nip) continue;
        b[n] = 0;
        u_short port = ntohs(from.sin_port);

        if (port == 137 && !got_nb && n >= 57) {
            got_nb = 1;
            int p = dns_skip(b, n, 12) + 10;
            if (p >= n) continue;
            int cnt = b[p++], named = 0;
            for (int i = 0; i < cnt && p + 18 <= n; i++, p += 18) {
                BYTE *e = b + p;
                if (!named && e[15] == 0x00 && !(e[16] & 0x80)) {
                    memcpy(u->nb, e, 15); u->nb[15] = 0;
                    for (int k = 14; k >= 0 && u->nb[k] == ' '; k--) u->nb[k] = 0;
                    named = 1;
                }
            }
            if (p + 6 <= n) memcpy(u->nbmac, b + p, 6);
        } else if (port == 161 && !got_snmp) {
            got_snmp = 1;
            static const BYTE oid[10] = { 0x06, 0x08, 0x2B, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00 };
            for (int p = 0; p + 12 <= n; p++) {
                int k = 0; while (k < 10 && b[p + k] == oid[k]) k++;
                if (k < 10) continue;
                p += 10;
                if (b[p++] != 0x04) break;
                int len = b[p++];
                if (len == 0x81) len = b[p++];
                else if (len == 0x82) { len = (b[p] << 8) | b[p + 1]; p += 2; }
                if (p + len > n) len = n - p;
                for (int i = 0; i < len; i++) if (b[p + i] < 32) b[p + i] = ' ';
                u->descr[0] = 0; sappend(u->descr, sizeof u->descr, (const char *)b + p, len);
                break;
            }
        } else if (port == 5353 && !got_md && n > 12) {
            got_md = 1;
            int qd = (b[4] << 8) | b[5], an = (b[6] << 8) | b[7], p = 12;
            for (int i = 0; i < qd; i++) p = dns_skip(b, n, p) + 4;
            for (int i = 0; i < an && p + 10 <= n; i++) {
                p = dns_skip(b, n, p);
                if (p + 10 > n) break;
                int type = (b[p] << 8) | b[p + 1], rdl = (b[p + 8] << 8) | b[p + 9];
                p += 10;
                if (type == 12) {
                    dns_name(b, n, p, u->mdns, sizeof u->mdns);
                    int l = slen(u->mdns);
                    if (l > 6 && ci_find(u->mdns + l - 6, ".local")) u->mdns[l - 6] = 0;
                    break;
                }
                p += rdl;
            }
        } else if (port == 1900 || ci_find((const char *)b, "<multicastsearchresult") || ci_find((const char *)b, "http/1.1 200") == (const char *)b) {
            disc_parse(b, n, &u->w);
            if (u->w.maker[0] || ci_find((const char *)b, "<multicastsearchresult") || u->w.location[0]) got_ssdp = 1;
        } else if (port == 3702 && !got_wsd) {
            got_wsd = 1;
            disc_parse(b, n, &u->w);
        }
        }
        if (round >= 1) return;
    }
}

static int http_req(DWORD ip, u_short port, const char *req, int rl, char *buf, int cap) {
    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) return 0;
    u_long nbio = 1; ioctlsocket(s, FIONBIO, &nbio);
    struct sockaddr_in sa = {0};
    sa.sin_family = AF_INET; sa.sin_port = htons(port); sa.sin_addr.s_addr = htonl(ip);
    connect(s, (struct sockaddr *)&sa, sizeof sa);
    DWORD t0 = GetTickCount();
    fd_set wf; FD_ZERO(&wf); FD_SET(s, &wf);
    struct timeval tv = { 1, 0 };
    int n = 0;
    if (select(0, NULL, &wf, NULL, &tv) == 1) {
        send(s, req, rl, 0);
        while (n < cap - 1) {
            int left = HTTP_MS - (int)(GetTickCount() - t0);
            if (left <= 0) break;
            fd_set rf; FD_ZERO(&rf); FD_SET(s, &rf);
            struct timeval t2 = { 0, left * 1000 };
            if (select(0, &rf, NULL, NULL, &t2) <= 0) break;
            int k = recv(s, buf + n, cap - 1 - n, 0);
            if (k <= 0) break;
            n += k;
        }
    }
    buf[n] = 0;
    closesocket(s);
    return n;
}

static int http_get(DWORD ip, u_short port, char *buf, int cap) {
    char req[200];
    int rl = wsprintfA(req, "GET / HTTP/1.0\r\nHost: %u.%u.%u.%u\r\nUser-Agent: Mozilla/5.0\r\n"
                            "Accept: */*\r\nConnection: close\r\n\r\n",
                       ip >> 24, (ip >> 16) & 255, (ip >> 8) & 255, ip & 255);
    return http_req(ip, port, req, rl, buf, cap);
}

static const char *after_headers(const char *b) { const char *p = ci_find(b, "\r\n\r\n"); return p ? p + 4 : b; }

/* ---------- ONVIF ---------- */
typedef struct { char user[64], pass[64]; } CRED;          /* UTF-8 pair for ONVIF digest */
enum { P_FS, P_RDP, P_SSH, P_CAM, P_NPROTO };
static const WCHAR *PROTO_NAME[P_NPROTO] = { L"FileShare", L"RDP", L"SSH", L"Cameras" };
typedef struct { WCHAR label[40], user[64], pass[64]; int proto; } PROF;
static PROF g_prof[100]; static int g_nprof;
/* camera-protocol profiles, converted to UTF-8 CREDs for the ONVIF digest */
static int cam_creds(CRED *out, int max) {
    int n = 0;
    for (int i = 0; i < g_nprof && n < max; i++)
        if (g_prof[i].proto == P_CAM) {
            WideCharToMultiByte(CP_UTF8, 0, g_prof[i].user, -1, out[n].user, 64, NULL, NULL);
            WideCharToMultiByte(CP_UTF8, 0, g_prof[i].pass, -1, out[n].pass, 64, NULL, NULL);
            n++;
        }
    return n;
}

typedef struct {
    char maker[40], model[64], fw[48], name[64], osd[64];
    int capnvr, vsources, found, authed;
} ONV;

static int soap_call(DWORD ip, u_short port, const char *path, const char *hdr, const char *body, char *buf, int cap) {
    int el = slen(hdr) + slen(body) + 200;
    char *env = (char *)xalloc(el), *req = (char *)xalloc(el + 400);
    cat(env, el, "<?xml version=\"1.0\" encoding=\"UTF-8\"?><s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\">");
    cat(env, el, hdr);
    cat(env, el, "<s:Body>"); cat(env, el, body); cat(env, el, "</s:Body></s:Envelope>");
    wsprintfA(req, "POST %s HTTP/1.1\r\nHost: %u.%u.%u.%u:%u\r\nContent-Type: application/soap+xml; charset=utf-8\r\n"
                   "Content-Length: %d\r\nConnection: close\r\n\r\n",
              path, ip >> 24, (ip >> 16) & 255, (ip >> 8) & 255, ip & 255, port, slen(env));
    cat(req, el + 400, env);
    int n = http_req(ip, port, req, slen(req), buf, cap);
    xfree(env); xfree(req);
    return n;
}

static void b64(const BYTE *d, DWORD n, char *out, DWORD cap) {
    out[0] = 0;
    if (!CryptBinaryToStringA(d, n, CRYPT_STRING_BASE64, out, &cap)) { out[0] = 0; return; }
    int k = 0;                                   /* drop CR/LF (XP has no NOCRLF flag) */
    for (int i = 0; out[i]; i++) if (out[i] != '\r' && out[i] != '\n') out[k++] = out[i];
    out[k] = 0;
}

/* WS-Security UsernameToken with PasswordDigest = Base64(SHA1(nonce + created + password)) */
static int ws_header(char *out, int cap, const CRED *c, const char *created) {
    HCRYPTPROV prov; HCRYPTHASH h;
    BYTE nonce[16], dig[20]; DWORD dl = 20;
    if (!CryptAcquireContextW(&prov, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) return 0;
    CryptGenRandom(prov, 16, nonce);
    int ok = CryptCreateHash(prov, CALG_SHA1, 0, 0, &h);
    if (ok) {
        CryptHashData(h, nonce, 16, 0);
        CryptHashData(h, (const BYTE *)created, slen(created), 0);
        CryptHashData(h, (const BYTE *)c->pass, slen(c->pass), 0);
        ok = CryptGetHashParam(h, HP_HASHVAL, dig, &dl, 0);
        CryptDestroyHash(h);
    }
    CryptReleaseContext(prov, 0);
    if (!ok) return 0;
    char n64[40], d64[40];
    b64(nonce, 16, n64, sizeof n64); b64(dig, 20, d64, sizeof d64);
    wsprintfA(out,
        "<s:Header><Security s:mustUnderstand=\"1\" xmlns=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd\">"
        "<UsernameToken><Username>%s</Username>"
        "<Password Type=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest\">%s</Password>"
        "<Nonce EncodingType=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary\">%s</Nonce>"
        "<Created xmlns=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\">%s</Created>"
        "</UsernameToken></Security></s:Header>", c->user, d64, n64, created);
    (void)cap;
    return 1;
}

static void parse_url(const char *url, u_short *port, char *path, int pcap) {
    const char *p = ci_find(url, "http://");
    if (!p) return;
    p += 7;
    while (*p && *p != ':' && *p != '/' && *p != ' ') p++;
    *port = 80;
    if (*p == ':') { *port = 0; for (p++; *p >= '0' && *p <= '9'; p++) *port = (u_short)(*port * 10 + (*p - '0')); }
    int n = 0;
    if (*p == '/') while (p[n] && p[n] != ' ' && n < pcap - 1) { path[n] = p[n]; n++; }
    if (!n) path[n++] = '/';
    path[n] = 0;
}

static int devinfo(const char *body, ONV *o) {
    if (!ci_find(body, "getdeviceinformationresponse")) return 0;
    char t[64];
    xml_text(body, "manufacturer", t, sizeof t); if (t[0]) { o->maker[0] = 0; sappend(o->maker, sizeof o->maker, t, -1); }
    xml_text(body, "model", t, sizeof t);        if (t[0]) { o->model[0] = 0; sappend(o->model, sizeof o->model, t, -1); }
    xml_text(body, "firmwareversion", t, sizeof t); if (t[0]) { o->fw[0] = 0; sappend(o->fw, sizeof o->fw, t, -1); }
    return 1;
}

static int onvif_query(DWORD ip, const char *xaddr, int port80, char *buf, int cap, ONV *o, char *dbg, int dcap) {
    u_short port = 80; char path[128] = "/onvif/device_service";
    if (ci_find(xaddr, "http://")) parse_url(xaddr, &port, path, sizeof path);
    else if (!port80) return 0;

    static const char caps[] = "<GetCapabilities xmlns=\"http://www.onvif.org/ver10/device/wsdl\"><Category>All</Category></GetCapabilities>";
    static const char info[] = "<GetDeviceInformation xmlns=\"http://www.onvif.org/ver10/device/wsdl\"/>";
    static const char hname[] = "<GetHostname xmlns=\"http://www.onvif.org/ver10/device/wsdl\"/>";
    static const char getosd[] = "<GetOSDs xmlns=\"http://www.onvif.org/ver10/media/wsdl\"/>";
    static const char getosd2[] = "<GetOSDs xmlns=\"http://www.onvif.org/ver20/media/wsdl\"/>";
    static const char tme[]  = "<GetSystemDateAndTime xmlns=\"http://www.onvif.org/ver10/device/wsdl\"/>";
    static const char vsrc[] = "<GetVideoSources xmlns=\"http://www.onvif.org/ver10/media/wsdl\"/>";
    char media[160] = "";

    if (soap_call(ip, port, path, "", caps, buf, cap)) {
        const char *body = after_headers(buf);
        if (dbg) { cat(dbg, dcap, "  onvif caps: "); cat(dbg, dcap, body); cat(dbg, dcap, "\r\n"); }
        if (ci_find(body, "capabilities")) {
            o->found = 1;
            if (ci_find(body, ":receiver>") || ci_find(body, "<receiver>")) o->capnvr = 1;
            char vs[16]; xml_text(body, "videosources", vs, sizeof vs);
            int c = 0; for (const char *v = vs; *v >= '0' && *v <= '9'; v++) c = c * 10 + (*v - '0');
            if (c > 1) o->capnvr = 1;
            const char *m = ci_find(body, ":media>");
            if (m) xml_text(m, "xaddr", media, sizeof media);
        }
    }
    if (soap_call(ip, port, path, "", info, buf, cap)) {
        const char *body = after_headers(buf);
        if (dbg) { cat(dbg, dcap, "  onvif info: "); cat(dbg, dcap, body); cat(dbg, dcap, "\r\n"); }
        if (devinfo(body, o)) o->found = 1;
    }
    /* Authenticate to read the OSD even when the model already identifies a camera.
       Model recognition must never suppress the actual camera-name lookup. */
    CRED cc[32]; int nc = cam_creds(cc, 32);
    if (nc && (o->found || port80)) {
        char created[32];
        SYSTEMTIME st; GetSystemTime(&st);
        int Y = st.wYear, M = st.wMonth, D = st.wDay, h = st.wHour, mi = st.wMinute, sec = st.wSecond;
        if (soap_call(ip, port, path, "", tme, buf, cap)) {      /* use the device clock: digests are time-checked */
            const char *u = ci_find(after_headers(buf), "utcdatetime");
            if (u) {
                char t[8];
                xml_text(u, "year", t, 8);   if (t[0]) Y = (int)(t[0]-'0')*1000 + (t[1]-'0')*100 + (t[2]-'0')*10 + (t[3]-'0');
                const char *tags[5] = { "month", "day", "hour", "minute", "second" };
                int *vals[5] = { &M, &D, &h, &mi, &sec };
                for (int i = 0; i < 5; i++) {
                    xml_text(u, tags[i], t, 8);
                    if (t[0]) { int v = 0; for (char *q = t; *q >= '0' && *q <= '9'; q++) v = v * 10 + (*q - '0'); *vals[i] = v; }
                }
            }
        }
        wsprintfA(created, "%04d-%02d-%02dT%02d:%02d:%02dZ", Y, M, D, h, mi, sec);
        char *hdr = (char *)xalloc(2048);
        for (int i = 0; i < nc && !o->authed; i++) {
            if (!ws_header(hdr, 2048, &cc[i], created)) break;
            if (soap_call(ip, port, path, hdr, info, buf, cap) && devinfo(after_headers(buf), o)) {
                o->found = o->authed = 1;
                if (dbg) { cat(dbg, dcap, "  onvif auth info: "); cat(dbg, dcap, after_headers(buf)); cat(dbg, dcap, "\r\n"); }
                ws_header(hdr, 2048, &cc[i], created);           /* configured device name */
                if (soap_call(ip, port, path, hdr, hname, buf, cap)) {
                    const char *hb = ci_find(after_headers(buf), "hostnameinformation");
                    if (hb) { char nm[64]; xml_text(hb, "name", nm, sizeof nm); if (nm[0]) { o->name[0] = 0; sappend(o->name, sizeof o->name, nm, -1); } }
                    if (dbg) { cat(dbg, dcap, "  onvif hostname: "); cat(dbg, dcap, o->name); cat(dbg, dcap, "\r\n"); }
                }
                {
                    u_short mp = port; char mpath[128] = "/onvif/media_service";
                    if (media[0]) parse_url(media, &mp, mpath, sizeof mpath);
                    ws_header(hdr, 2048, &cc[i], created);
                    if (soap_call(ip, mp, mpath, hdr, vsrc, buf, cap)) {
                        const char *body = after_headers(buf);
                        if (dbg) { cat(dbg, dcap, "  onvif videosources: "); cat(dbg, dcap, body); cat(dbg, dcap, "\r\n"); }
                        int c = 0;
                        for (const char *q = body; (q = ci_find(q, "videosources token")) != NULL; q++) c++;
                        o->vsources = c;
                        if (c > 1) o->capnvr = 1;
                    }
                    ws_header(hdr, 2048, &cc[i], created);        /* OSD overlay text (the on-screen name) */
                    int osdr = soap_call(ip, mp, mpath, hdr, getosd, buf, cap);
                    if (!osdr || !ci_find(after_headers(buf), "getosdsresponse"))
                        osdr = soap_call(ip, mp, mpath, hdr, getosd2, buf, cap);
                    if (osdr) {
                        const char *body = after_headers(buf);
                        char t[64]; xml_text(body, "plaintext", t, sizeof t);
                        if (!t[0]) xml_text(body, "textstring", t, sizeof t);
                        if (t[0]) { o->osd[0] = 0; sappend(o->osd, sizeof o->osd, t, -1); }
                        if (dbg) { cat(dbg, dcap, "  onvif osd: "); cat(dbg, dcap, o->osd); cat(dbg, dcap, "\r\n"); }
                    }
                }
            }
        }
        xfree(hdr);
    }
    return o->found;
}

/* UPnP device description: <manufacturer>, <modelName>, <deviceType> */
static void upnp_desc(DWORD ip, const char *location, char *buf, int cap, WSDI *w, char *dtype, int dcap) {
    u_short port = 80; char path[160] = "/";
    if (!ci_find(location, "http://")) return;
    char host[20]; wsprintfA(host, "%u.%u.%u.%u", ip >> 24, (ip >> 16) & 255, (ip >> 8) & 255, ip & 255);
    if (!ci_find(location, host)) return;              /* only describe the host itself */
    parse_url(location, &port, path, sizeof path);
    char req[300];
    int rl = wsprintfA(req, "GET %s HTTP/1.0\r\nHost: %s:%u\r\nConnection: close\r\n\r\n", path, host, port);
    if (!http_req(ip, port, req, rl, buf, cap)) return;
    const char *b = after_headers(buf);
    char t[64];
    xml_text(b, "manufacturer", t, sizeof t); setf(w->maker, sizeof w->maker, t);
    xml_text(b, "modelname", t, sizeof t);    setf(w->model, sizeof w->model, t);
    xml_text(b, "devicetype", dtype, dcap);
    xml_text(b, "friendlyname", t, sizeof t); setf(w->friendly, sizeof w->friendly, t);
}



/* pull Server header, auth realm and <title> out of an HTTP response */
static void http_parse(char *b, char *server, char *realm, char *title, int cap) {
    const char *p;
    char *body = (char *)ci_find(b, "\r\n\r\n");
    if (body) *body = 0;                                  /* search headers only first */
    if ((p = ci_find(b, "\nserver:")) != NULL) {
        p += 8; int n = 0; while (p[n] && p[n] != '\r' && p[n] != '\n') n++;
        sappend(server, cap, p, n);
    }
    if ((p = ci_find(b, "realm=\"")) != NULL) {
        p += 7; int n = 0; while (p[n] && p[n] != '"' && p[n] != '\r') n++;
        sappend(realm, cap, p, n);
    }
    if (body) {
        *body = '\r';
        if ((p = ci_find(body, "<title")) != NULL && (p = ci_find(p, ">")) != NULL) {
            p++; int n = 0; while (p[n] && p[n] != '<') n++;
            sappend(title, cap, p, n);
        }
    }
}

typedef struct { const char *kw, *type; } RULE;

/* keywords in HTTP title/server/realm or SNMP sysDescr (lower case, checked in order) */
static const RULE BANNER[] = {
    {"jetdirect","Printer"},{"laserjet","Printer"},{"officejet","Printer"},{"deskjet","Printer"},
    {"pagewide","Printer"},{"printer","Printer"},{"imagerunner","Printer"},{"workcentre","Printer"},
    {"bizhub","Printer"},{"ecosys","Printer"},{"mfp","Printer"},{"epson","Printer"},{"brother","Printer"},
    {"kyocera","Printer"},{"ricoh","Printer"},{"lexmark","Printer"},{"xerox","Printer"},{"konica","Printer"},
    {"nvr","NVR / DVR"},{"dvr","NVR / DVR"},{"video recorder","NVR / DVR"},
    {"ip camera","IP camera"},{"ipcam","IP camera"},{"network camera","IP camera"},{"netsurveillance","IP camera"},
    {"webcam","IP camera"},{"hikvision","IP camera"},{"dahua","IP camera"},{"tiandy","IP camera"},
    {"integrated lights","Server mgmt (iLO)"},{"hp ilo","Server mgmt (iLO)"},{"ilo 4","Server mgmt (iLO)"},
    {"ilo 5","Server mgmt (iLO)"},{"idrac","Server mgmt (iDRAC)"},{"ipmi","Server mgmt (BMC)"},
    {"megarac","Server mgmt (BMC)"},
    {"esxi","Hypervisor (ESXi)"},{"vmware","Hypervisor (ESXi)"},{"proxmox","Hypervisor"},
    {"synology","NAS"},{"diskstation","NAS"},{"qnap","NAS"},{"truenas","NAS"},
    {"smart-ups","UPS"},{"network management card","UPS"},{"powerchute","UPS"},
    {"routeros","Network device"},{"mikrotik","Network device"},{"cisco ios","Network device"},
    {"adaptive security","Firewall"},{"cisco asa","Firewall"},{"fortigate","Firewall"},{"pfsense","Firewall"},
    {"unifi","Network device"},{"edgeos","Network device"},{"zyxel","Network device"},{"procurve","Network device"},
    {"juniper","Network device"},{"aruba","Network device"},{"switch","Network device"},{"router","Network device"},
    {"access point","Network device"},{"firewall","Firewall"},
    {"canon","Printer"},{"internetgatewaydevice","Network device"},{"wlanaccesspoint","Network device"},
    {"mediarenderer","TV / media"},{"inverter","Solar inverter"},{"fronius","Solar inverter"},
    {"microsoft-iis","Windows server"},{"windows","Windows PC"},
    {0,0}
};
/* keywords in the MAC vendor name (lower case, checked in order) */
static const RULE VENDOR[] = {
    {"hikvision","IP camera"},{"dahua","IP camera"},{"tiandy","IP camera"},{"uniview","IP camera"},
    {"tvt","IP camera"},{"xiongmai","IP camera"},{"axis comm","IP camera"},{"hanwha","IP camera"},
    {"techwin","IP camera"},{"vivotek","IP camera"},{"avigilon","IP camera"},{"milesight","IP camera"},
    {"reolink","IP camera"},{"foscam","IP camera"},{"amcrest","IP camera"},{"lorex","IP camera"},
    {"geovision","IP camera"},{"mobotix","IP camera"},{"jovision","IP camera"},{"sunell","IP camera"},
    {"kedacom","IP camera"},{"ezviz","IP camera"},{"imou","IP camera"},{"provision","IP camera"},
    {"brother","Printer"},{"canon","Printer"},{"epson","Printer"},{"kyocera","Printer"},{"ricoh","Printer"},
    {"xerox","Printer"},{"lexmark","Printer"},{"konica","Printer"},{"oki data","Printer"},{"zebra","Printer"},
    {"pantum","Printer"},{"toshiba tec","Printer"},
    {"cisco","Network device"},{"mikrotik","Network device"},{"routerboard","Network device"},
    {"tp-link","Network device"},{"ubiquiti","Network device"},{"juniper","Network device"},
    {"aruba","Network device"},{"netgear","Network device"},{"zyxel","Network device"},{"d-link","Network device"},
    {"ruckus","Network device"},{"fortinet","Firewall"},{"sonicwall","Firewall"},{"palo alto","Firewall"},
    {"h3c","Network device"},{"ruijie","Network device"},{"tenda","Network device"},{"edimax","Network device"},
    {"allied telesis","Network device"},{"extreme net","Network device"},{"arista","Network device"},
    {"cambium","Network device"},{"teltonika","Network device"},{"draytek","Network device"},
    {"vmware","Virtual machine"},{"pcs systemtechnik","Virtual machine"},{"parallels","Virtual machine"},
    {"xensource","Virtual machine"},{"nutanix","Virtual machine"},
    {"super micro","Server"},{"supermicro","Server"},
    {"american power","UPS"},{"schneider","UPS"},{"eaton","UPS"},
    {"synology","NAS"},{"qnap","NAS"},
    {"raspberry","Raspberry Pi"},{"espressif","IoT device"},{"tuya","IoT device"},
    {"apple","Apple device"},{"samsung","Phone / tablet"},{"xiaomi","Phone / tablet"},{"oppo","Phone / tablet"},
    {"vivo mobile","Phone / tablet"},{"oneplus","Phone / tablet"},{"motorola mob","Phone / tablet"},
    {"huawei device","Phone / tablet"},{"honor device","Phone / tablet"},{"realme","Phone / tablet"},
    {"asustek","PC"},{"giga-byte","PC"},{"gigabyte","PC"},{"micro-star","PC"},{"asrock","PC"},
    {"elitegroup","PC"},{"intel","PC"},{"realtek","PC"},{"dell","PC"},{"lenovo","PC"},{"hewlett","PC"},
    {"hp inc","PC"},{"fujitsu","PC"},{"acer","PC"},{"biostar","PC"},{"quanta","PC"},{"wistron","PC"},
    {"compal","PC"},{"liteon","PC"},{"azurewave","PC"},{"pegatron","PC"},{"clevo","PC"},{"shuttle","PC"},
    {"fronius","Solar inverter"},{"sma solar","Solar inverter"},{"ligowave","Network device"},{"mimosa","Network device"},
    {"(private","Mobile device"},
    {0,0}
};

static const char *match(const RULE *r, const char *text) {
    if (!*text) return NULL;
    for (; r->kw; r++) if (ci_find(text, r->kw)) return r->type;
    return NULL;
}

static int is_cam(const char *t) { return t && ((t[0] == 'I' && t[1] == 'P') || (t[0] == 'N' && t[1] == 'V')); }
static int is_net(const char *t) { return t && ((t[0] == 'N' && t[1] == 'e') || t[0] == 'F'); }

typedef struct {
    const char *vendor, *banner;
    int netbios, snmp, onvif, nvr, wsd_printer, wsd_pc, cam_brand;
} EVID;

static const char *classify(const RES *r, const BYTE *mac, int hasmac, const EVID *e) {
    DWORD P = r->ports;
#define HAS(port) (P & pbit(port))
    if (hasmac) {                                   /* well-known virtual NIC prefixes */
        DWORD o = (mac[0] << 16) | (mac[1] << 8) | mac[2];
        if (o == 0x00155D || o == 0x005056 || o == 0x000C29 || o == 0x000569 || o == 0x080027 || o == 0x001C42)
            return "Virtual machine";
    }
    const char *bt = match(BANNER, e->banner), *t = match(VENDOR, e->vendor);
    if (e->wsd_printer) return "Printer";           /* WS-Discovery "PrintDeviceType" */
    if (bt && !is_cam(bt) && !e->onvif) return bt;
    /* video devices: ONVIF, RTSP or DVR ports, or a camera brand. Checked before printer ports,
       because many cameras and NVRs also listen on 9100. */
    if (e->onvif || HAS(554) || HAS(34567) || HAS(37777) || is_cam(bt) || is_cam(t))
        return (e->nvr || (bt && bt[0] == 'N')) ? "NVR / DVR" : "IP camera";
    if (HAS(9100) || HAS(515) || HAS(631)) return "Printer";
    if (HAS(88) && HAS(389)) return "Domain controller";
    if (HAS(8291)) return "Network device";
    /* TP-Link, Cisco, ... also make Wi-Fi/LAN cards: only trust the brand with a management port */
    if (is_net(t) && !(P & (pbit(80) | pbit(443) | pbit(22) | pbit(23) | pbit(8080) | pbit(8443))) && !e->snmp) t = NULL;
    int win = e->wsd_pc || HAS(3389) || HAS(135) || ((HAS(445) || e->netbios) && r->ttl > 64);
    if (t && t[0] != 'P' && t[0] != 'M') return t;              /* anything but "PC" / "Mobile device" */
    if (t && t[0] == 'P' && t[1] == 'h') return t;              /* "Phone / tablet" */
    if (win) return HAS(53) ? "Windows server" : "Windows PC";
    if (t) return (t[1] == 'C' && r->ttl > 0 && r->ttl <= 64) ? "Linux PC" : t;
    if (r->ttl > 128) return "Network device";
    if (r->ttl > 64) return "Windows PC";
    if (r->ttl > 0 || HAS(22)) return "Linux / embedded";
    return "";
#undef HAS
}

static void post(RES *r) {
    RES *h = (RES *)xalloc(sizeof *r);
    *h = *r;
    if (!PostMessageW(g_wnd, WM_RESULT, 0, (LPARAM)h)) xfree(h);
}

static void probe(DWORD ip, HANDLE icmp, SOCKET us, char *http) {
    RES r; memset(&r, 0, sizeof r);
    r.ip = ip; r.rtt = -1;
    ip2w(ip, r.ips);
    DWORD nip = htonl(ip);
    BYTE mac[6] = {0}; int hasmac = 0, alive = 0, scanned = 0;

    for (int i = 0; i < g_nif; i++)
        if (g_if[i].ip == ip) { memcpy(mac, g_if[i].mac, 6); hasmac = alive = 1; r.rtt = 0; r.ttl = 128; }

    int local = on_link(ip);
    if (!alive && local) {
        ULONG m[2], len = 6;
        if (SendARP(nip, 0, m, &len) == NO_ERROR && len == 6) { memcpy(mac, m, 6); hasmac = alive = 1; }
    }
    if (g_stop) return;
    if (!local || alive) {
        char data[16] = "ipscan-ping";
        BYTE rep[sizeof(ICMP_ECHO_REPLY) + 64];
        if (icmp != INVALID_HANDLE_VALUE &&
            IcmpSendEcho(icmp, nip, data, sizeof data, NULL, rep, sizeof rep, PING_MS)) {
            ICMP_ECHO_REPLY *e = (ICMP_ECHO_REPLY *)rep;
            if (e->Status == IP_SUCCESS && e->Address == nip) {
                alive = 1;
                if (r.rtt < 0) { r.rtt = (int)e->RoundTripTime; r.ttl = e->Options.Ttl; }
            }
        }
    }
    if (!alive && !local && !g_stop) { r.ports = port_scan(nip, &alive); scanned = 1; }
    if (g_stop) return;
    if (!alive) { post(&r); return; }

    r.alive = 1;
    if (!scanned) r.ports = port_scan(nip, &alive);

    struct sockaddr_in sa = {0};
    sa.sin_family = AF_INET; sa.sin_addr.s_addr = nip;
    WCHAR host[256];
    if (GetNameInfoW((SOCKADDR *)&sa, sizeof sa, host, 256, NULL, 0, NI_NAMEREQD) == 0)
        lstrcpynW(r.name, host, 64);

    /* give the multicast WS-Discovery listener time to collect answers */
    while (!g_wsd_done && !g_stop && GetTickCount() - g_scan_t0 < 1500) Sleep(25);
    static const UDPI zero_u;
    UDPI u = zero_u;
    wsd_find(nip, &u.w);
    udp_info(us, nip, &u);

    if (!r.name[0] && u.nb[0])   MultiByteToWideChar(CP_OEMCP, 0, u.nb, -1, r.name, 64);
    if (!r.name[0] && u.mdns[0]) MultiByteToWideChar(CP_UTF8, 0, u.mdns, -1, r.name, 64);
    if (!r.name[0]) {                                   /* ONVIF device name scope (cameras / NVRs) */
        const char *nm = ci_find(u.w.scopes, "/name/");
        if (nm) { nm += 6; char t[64]; int k = 0; while (nm[k] && nm[k] != ' ' && k < 63) { t[k] = nm[k]; k++; } t[k] = 0;
                  if (t[0]) MultiByteToWideChar(CP_UTF8, 0, t, -1, r.name, 64); }
    }
    if (!hasmac && (u.nbmac[0] | u.nbmac[1] | u.nbmac[2] | u.nbmac[3] | u.nbmac[4] | u.nbmac[5])) {
        memcpy(mac, u.nbmac, 6); hasmac = 1;
    }

    char server[96] = "", realm[96] = "", title[96] = "";
    static const u_short web[] = { 80, 8080, 8000, 5000 };
    for (int i = 0; i < 4 && !g_stop; i++)
        if (r.ports & pbit(web[i])) {
            if (http_get(ip, web[i], http, 8192)) http_parse(http, server, realm, title, 96);
            break;
        }

    char *dbg = g_debug ? (char *)xalloc(12000) : NULL;
    const char *vend = hasmac ? vendor_of(mac) : "";
    EVID ev = {0};
    ev.vendor = vend; ev.netbios = u.nb[0] != 0; ev.snmp = u.descr[0] != 0;
    ev.wsd_printer = ci_find(u.w.types, "print") != NULL;
    ev.wsd_pc = ci_find(u.w.types, "computer") != NULL;
    ev.onvif = wsd_onvif(&u.w);
    ONV o; memset(&o, 0, sizeof o);
    int vkind = u.w.kind[0] != 0;                      /* a vendor search protocol said IPC / NVR / DVR */
    if (vkind) ev.onvif = 1;
    if (!g_stop && !ev.wsd_printer && !ev.wsd_pc &&
        (ev.onvif || (r.ports & (pbit(554) | pbit(34567) | pbit(37777))) || is_cam(match(VENDOR, vend))))
        ev.onvif |= onvif_query(ip, wsd_onvif(&u.w) ? u.w.xaddr : "", (r.ports & pbit(80)) != 0, http, 8192, &o, dbg, 12000);
    char dtype[96] = "";
    if (!g_stop && u.w.location[0] && !u.w.vendor) upnp_desc(ip, u.w.location, http, 8192, &u.w, dtype, sizeof dtype);

    /* real device maker / model: vendor search protocol > ONVIF > UPnP > ONVIF scopes > web fingerprint */
    char dmaker[48] = "", dmodel[64] = "", fw[48] = "";
    if (u.w.vendor) { sappend(dmaker, 48, u.w.maker, -1); sappend(dmodel, 64, u.w.model, -1); }
    if (!dmodel[0] && (o.maker[0] || o.model[0])) {
        if (!dmaker[0]) sappend(dmaker, 48, o.maker, -1);
        sappend(dmodel, 64, o.model, -1);
    }
    if (!dmaker[0] && !dmodel[0] && u.w.maker[0]) { sappend(dmaker, 48, u.w.maker, -1); sappend(dmodel, 64, u.w.model, -1); }
    if (!dmodel[0]) {
        const char *h = ci_find(u.w.scopes, "/hardware/");
        if (h) { h += 10; int n = 0; while (h[n] && h[n] != ' ') n++; sappend(dmodel, 64, h, n); }
    }
    if (!dmaker[0] || ci_find(dmaker, "hisi")) {
        static const RULE FP[] = { {"net video browser","Tiandy"},{"tiandy","Tiandy"},{"netsurveillance","XiongMai"},
                                   {"herospeed","Herospeed"},{"hikvision","Hikvision"},{"dahua","Dahua"},{0,0} };
        char fpt[300] = "";
        sappend(fpt, 300, title, -1); sappend(fpt, 300, " ", -1); sappend(fpt, 300, server, -1);
        sappend(fpt, 300, " ", -1); sappend(fpt, 300, u.w.scopes, -1);
        const char *mk = match(FP, fpt);
        if (mk) { dmaker[0] = 0; sappend(dmaker, 48, mk, -1); }
    }
    if (!lstrcmpiA(dmodel, "hisi")) dmodel[0] = 0;      /* chip vendor, not a model */
    sappend(fw, 48, u.w.fw[0] ? u.w.fw : o.fw, -1);
    char device[112] = "";
    {   /* "maker model", without repeating the maker when the model already starts with it */
        char first[24]; int k = 0;
        while (dmaker[k] && dmaker[k] != ' ' && k < 23) { first[k] = lc(dmaker[k]); k++; }
        first[k] = 0;
        if (dmaker[0] && !(dmodel[0] && ci_find(dmodel, first))) join(device, 112, " ", dmaker);
        join(device, 112, " ", dmodel);
    }

    /* recorder or camera: vendor protocol first, then the device name (maker+model+UPnP type), then ONVIF */
    char devtext[300] = "";
    join(devtext, 300, " ", device); join(devtext, 300, " ", u.w.maker); join(devtext, 300, " ", u.w.model);
    join(devtext, 300, " ", dtype);  join(devtext, 300, " ", u.w.friendly);
    int tnvr = (ci_find(devtext, "tiandy") || ci_find(u.w.maker, "tiandy")) && (r.ports & pbit(443)) &&
               ci_find(server, "boa") && !ci_find(title, "net video browser");
    if (vkind) ev.nvr = u.w.kind[0] != 'I';
    else if (tnvr) ev.nvr = 1;
    else if (any_kw(devtext, CAM_KW)) ev.nvr = 0;
    else if (any_kw(devtext, NVR_KW) || any_kw(u.w.scopes, NVR_KW)) ev.nvr = 1;
    else ev.nvr = o.capnvr;

    char banner[600] = "";
    join(banner, 600, " | ", title); join(banner, 600, " | ", realm); join(banner, 600, " | ", server);
    join(banner, 600, " | ", u.descr); join(banner, 600, " | ", dtype); join(banner, 600, " | ", u.w.server);
    ev.banner = banner;

    const char *type = classify(&r, mac, hasmac, &ev);
    if (ci_find(type, "camera")) {                      /* IP cameras: OSD overlay text only, no generic name */
        r.name[0] = 0;
        if (o.osd[0]) MultiByteToWideChar(CP_UTF8, 0, o.osd, -1, r.name, 64);
    }
    /* Details = device, then what it told us about itself, then firmware */
    char info[240] = "";
    join(info, sizeof info, "", device);
    join(info, sizeof info, ",  ", u.descr[0] ? u.descr : title[0] ? title : realm[0] ? realm : server[0] ? server : u.w.server);
    if (fw[0]) { char f[56] = "FW "; sappend(f, 56, fw, -1); join(info, sizeof info, ",  ", f); }

    if (hasmac) {
        wsprintfW(r.mac, L"%02X:%02X:%02X:%02X:%02X:%02X", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
        MultiByteToWideChar(CP_ACP, 0, vend, -1, r.vendor, 32);
    }
    MultiByteToWideChar(CP_ACP, 0, type, -1, r.type, 24);
    lstrcpyW(r.autotype, r.type);
    r.confident = (vkind || tnvr || o.found || o.authed || o.capnvr || u.w.vendor ||
                   any_kw(dmodel, CAM_KW) || any_kw(dmodel, NVR_KW) || any_kw(u.w.scopes, NVR_KW));
    MultiByteToWideChar(CP_UTF8, 0, device, -1, r.autodev, 96); r.autodev[95] = 0;
    if (!MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, info, -1, r.info, 240))
        MultiByteToWideChar(CP_ACP, 0, info, -1, r.info, 240);
    r.info[239] = 0;
    if (r.rtt >= 0) wsprintfW(r.ping, r.rtt < 1 ? L"<1 ms" : L"%d ms", r.rtt);
    WCHAR *pw = r.portsw;
    for (int i = 0; i < NPORTS; i++)
        if ((r.ports >> i & 1) && pw - r.portsw < 56) pw += wsprintfW(pw, pw == r.portsw ? L"%u" : L",%u", PORTS[i]);

    if (dbg) {                                          /* diagnostics: everything the guess was based on */
        char *h = (char *)xalloc(16000), line[700];
        wsprintfA(line, "=== %u.%u.%u.%u  mac=%02X:%02X:%02X:%02X:%02X:%02X  vendor=%s  type=%s  ttl=%d  nvr=%d capnvr=%d onvif=%d authed=%d\r\n",
                  ip >> 24, (ip >> 16) & 255, (ip >> 8) & 255, ip & 255,
                  mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], vend, type, r.ttl, ev.nvr, o.capnvr, ev.onvif, o.authed);
        cat(h, 16000, line);
        char ports[200] = "";
        for (int i = 0; i < NPORTS; i++) if (r.ports >> i & 1) { char t[8]; wsprintfA(t, "%u ", PORTS[i]); cat(ports, 200, t); }
        wsprintfA(line, "  ports: %s\r\n  netbios: %s   mdns: %s\r\n  snmp: %s\r\n", ports, u.nb, u.mdns, u.descr); cat(h, 16000, line);
        wsprintfA(line, "  http server: %s\r\n  http realm: %s\r\n  http title: %s\r\n", server, realm, title); cat(h, 16000, line);
        cat(h, 16000, "  wsd types: "); cat(h, 16000, u.w.types);
        cat(h, 16000, "\r\n  wsd scopes: "); cat(h, 16000, u.w.scopes);
        cat(h, 16000, "\r\n  wsd xaddrs: "); cat(h, 16000, u.w.xaddr);
        cat(h, 16000, "\r\n  disc maker/model/kind/fw: "); cat(h, 16000, u.w.maker); cat(h, 16000, " / ");
        cat(h, 16000, u.w.model); cat(h, 16000, " / "); cat(h, 16000, u.w.kind); cat(h, 16000, " / "); cat(h, 16000, u.w.fw);
        cat(h, 16000, "\r\n  ssdp: "); cat(h, 16000, u.w.location); cat(h, 16000, "  "); cat(h, 16000, u.w.server);
        cat(h, 16000, "\r\n  upnp type: "); cat(h, 16000, dtype);
        cat(h, 16000, "\r\n  device: "); cat(h, 16000, device); cat(h, 16000, "\r\n");
        cat(h, 16000, dbg); cat(h, 16000, "\r\n");
        log_add(h);
        xfree(h); xfree(dbg);
    }

    InterlockedIncrement(&g_alive);
    post(&r);
}

static DWORD WINAPI worker(LPVOID p) {
    (void)p;
    HANDLE icmp = IcmpCreateFile();
    SOCKET us = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    char *http = (char *)xalloc(8192);
    for (;;) {
        if (g_stop) break;
        LONG i = InterlockedIncrement(&g_next) - 1;
        if (i >= g_total) break;
        probe(g_ips[i], icmp, us, http);
        InterlockedIncrement(&g_done);
    }
    xfree(http);
    if (us != INVALID_SOCKET) closesocket(us);
    if (icmp != INVALID_HANDLE_VALUE) IcmpCloseHandle(icmp);
    return 0;
}

static int add_ip(DWORD ip, int *cap) {
    if (g_total >= MAX_HOSTS) return 0;
    if (g_total >= *cap) {
        *cap = *cap ? *cap * 2 : 1024;
        g_ips = (DWORD *)xrealloc(g_ips, *cap * sizeof(DWORD));
    }
    g_ips[g_total++] = ip;
    return 1;
}
static int add_range(DWORD a, DWORD b, int *cap) {
    if (a > b) { DWORD t = a; a = b; b = t; }
    for (DWORD x = a;; x++) { if (!add_ip(x, cap)) return 0; if (x == b) break; }
    return 1;
}

static const WCHAR *parse_targets(WCHAR *txt) {
    static WCHAR bad[300];
    int cap = 0; g_total = 0;
    WCHAR *ctx = txt;
    for (WCHAR *t; (t = next_tok(&ctx)) != NULL;) {
        WCHAR *dash = wchr(t, '-'), *slash = wchr(t, '/');
        DWORD a, b;
        if (slash) {
            *slash = 0;
            const WCHAR *e; int bits = wnum(slash + 1, &e);
            if (!parse_ip(t, &a) || *e || bits < 8 || bits > 32) { *slash = '/'; goto fail; }
            DWORD mask = bits == 32 ? 0xFFFFFFFF : ~(0xFFFFFFFFu >> bits);
            DWORD net = a & mask, bc = net | ~mask;
            if (bits >= 31) { if (!add_range(net, bc, &cap)) break; }
            else if (!add_range(net + 1, bc - 1, &cap)) break;
        } else if (dash && parse_ip((*dash = 0, t), &a)) {
            WCHAR *r = dash + 1;
            if (!parse_ip(r, &b)) {
                const WCHAR *e; int last = wnum(r, &e);
                if (*e || last < 0 || last > 255) { *dash = '-'; goto fail; }
                b = (a & 0xFFFFFF00) | (DWORD)last;
            }
            if (!add_range(a, b, &cap)) break;
        } else {
            if (dash) *dash = '-';
            if (parse_ip(t, &a)) { if (!add_ip(a, &cap)) break; continue; }
            ADDRINFOW hints = {0}, *res = NULL, *r;
            hints.ai_family = AF_INET;
            if (GetAddrInfoW(t, NULL, &hints, &res) != 0) goto fail;
            for (r = res; r; r = r->ai_next)
                add_ip(ntohl(((struct sockaddr_in *)r->ai_addr)->sin_addr.s_addr), &cap);
            FreeAddrInfoW(res);
        }
        continue;
fail:
        lstrcpynW(bad, t, 300);
        return bad;
    }
    return NULL;
}

static DWORD WINAPI controller(LPVOID p) {
    WCHAR *txt = (WCHAR *)p;
    const WCHAR *bad = parse_targets(txt);
    xfree(txt);
    if (bad) {
        WCHAR *m = (WCHAR *)xalloc(400 * sizeof(WCHAR));
        wsprintfW(m, L"Cannot parse or resolve: \"%s\"", bad);
        PostMessageW(g_wnd, WM_ERRMSG, 0, (LPARAM)m);
        PostMessageW(g_wnd, WM_DONE, 0, 0);
        return 0;
    }
    load_interfaces();
    g_nwsd = 0; g_wsd_done = 0; g_scan_t0 = GetTickCount();
    if (!g_wsd) g_wsd = (WSD *)xalloc(2048 * sizeof(WSD));
    HANDLE lt = CreateThread(NULL, 0, wsd_listener, NULL, 0, NULL);
    int n = g_total < MAX_THREADS ? g_total : MAX_THREADS;
    HANDLE th[MAX_THREADS]; int nt = 0;
    for (int i = 0; i < n; i++) {
        HANDLE h = CreateThread(NULL, 64 * 1024, worker, NULL, 0, NULL);   /* 64 KB committed */
        if (h) th[nt++] = h;
    }
    for (int i = 0; i < nt; i++) { WaitForSingleObject(th[i], INFINITE); CloseHandle(th[i]); }
    if (lt) { WaitForSingleObject(lt, INFINITE); CloseHandle(lt); }
    PostMessageW(g_wnd, WM_DONE, 0, 0);
    return 0;
}

/* =====================================================================
 *  UI  (Office 2007 "blue" look, owner-drawn)
 * ===================================================================== */
enum { ID_EDIT = 100, ID_SCAN, ID_EXPORT, ID_ALIVE, ID_LIST, ID_LOGIN, ID_UPDATE, ID_SEARCH, ID_CEDIT,
       CM_COPYCELL = 200, CM_COPYIP, CM_COPYMAC, CM_COPYNAME, CM_COPYROW, CM_COMMENT, CM_COMMENTCLR,
       CM_VIEW, CM_HTTP, CM_HTTPS, CM_SMB, CM_RDP, CM_SSH, CM_PING, CM_TYPEAUTO = 300, CM_TYPE0 };
#define CM_SMB_OTHER 709
#define CM_MONBASE 700
#define CM_MONREMOVE 705
#define CM_BACKUP 706
#define CM_RESTORE 707
#define CM_DATAFOLDER 708
static const WCHAR *TYPES[] = { L"IP camera", L"NVR / DVR", L"Printer", L"Windows PC", L"Windows server",
    L"Domain controller", L"Network device", L"Firewall", L"Server", L"Server mgmt (iLO)", L"NAS", L"UPS",
    L"Phone / tablet", L"IoT device", L"Other", 0 };
enum { C_IP, C_NAME, C_MAC, C_VENDOR, C_COMMENT, C_TYPE, C_AUTH, C_PING, C_MON, C_PORTS, C_INFO, C_EVENTS, NCOLS };
static const WCHAR *COLNAME[NCOLS] = { L"IP", L"Name", L"MAC address", L"MAC maker", L"Comment", L"Type", L"Auth", L"Ping",
                                       L"Monitoring", L"Open ports", L"Details", L"Last 3 events" };
static const int COLW[NCOLS] = { 118, 140, 128, 135, 140, 105, 100, 52, 86, 95, 230, 240 };

#define CLR_TEXT     RGB(21, 66, 139)
#define CLR_BORDER   RGB(141, 178, 227)
#define CLR_DEADBG   RGB(255, 228, 228)
#define CLR_DEADTX   RGB(160, 50, 50)
#define CLR_ALTBG    RGB(242, 247, 254)

static HWND  g_edit, g_editinner, g_btn, g_exp, g_chk, g_login, g_upd, g_search, g_cedit, g_list, g_hot;
static WNDPROC g_ceditproc, g_innerproc; static int g_cedit_row = -1, g_cedit_multi;
static WCHAR g_filter[128];
static HFONT g_font, g_bold;
static WNDPROC g_btnproc;
static int   g_dpi = 96, g_alive_only = 1, g_ctxcol, g_updating;
static int   g_cat, g_tabhot = -1, g_tabcount[6];
static const WCHAR *TABNAME[6] = { L"All", L"NVR / DVR", L"IP cameras", L"PCs", L"RDP", L"Other" };
static DWORD g_t0, g_elapsed;
typedef struct { DWORD ip, generation; int seq, ok, rtt; } PipsPingDot;
static volatile LONG g_ping_generation;
static int g_ping_count, g_ping_ok[4], g_ping_ms[4], g_ping_active;
static DWORD g_ping_until;
static WCHAR g_ping_ip[16];
static WCHAR g_msg[160]; static DWORD g_msg_until; static volatile LONG g_share_busy;
static RES **g_res; static int g_nres, g_capres;
static int g_sortcol = C_IP, g_sortdir = 1;
static WCHAR g_ini[MAX_PATH], g_ini2[MAX_PATH];

#include "pips_monitor.inc"
#include "pips_osd.inc"
#include "pips_backup.inc"

static int S(int v) { return MulDiv(v, g_dpi, 96); }
static int PANEL_H(void) { return S(78); }
static int ROW1_Y(void) { return S(10); }
static int ROW2_Y(void) { return S(44); }
static int STATUS_H(void) { return S(26); }
static int TABW(void) { return S(208); }
static int TABH(void) { return S(34); }

static void grad(HDC dc, int l, int t, int r, int b, COLORREF c1, COLORREF c2) {
    TRIVERTEX v[2] = {
        { l, t, (COLOR16)(GetRValue(c1) << 8), (COLOR16)(GetGValue(c1) << 8), (COLOR16)(GetBValue(c1) << 8), 0 },
        { r, b, (COLOR16)(GetRValue(c2) << 8), (COLOR16)(GetGValue(c2) << 8), (COLOR16)(GetBValue(c2) << 8), 0 } };
    GRADIENT_RECT gr = { 0, 1 };
    GradientFill(dc, v, 2, &gr, 1, GRADIENT_FILL_RECT_V);
}
static void hline(HDC dc, int l, int r, int y, COLORREF c) {
    HPEN p = CreatePen(PS_SOLID, 1, c), o = SelectObject(dc, p);
    MoveToEx(dc, l, y, NULL); LineTo(dc, r, y);
    SelectObject(dc, o); DeleteObject(p);
}

static void paint_panel(HDC dc, int w) {
    int h = PANEL_H(), m = h * 2 / 5;
    grad(dc, 0, 0, w, m, RGB(232, 241, 253), RGB(218, 232, 252));
    grad(dc, 0, m, w, h, RGB(201, 220, 247), RGB(216, 231, 251));
    hline(dc, 0, w, h - 1, CLR_BORDER);
    SelectObject(dc, g_font); SetBkMode(dc, TRANSPARENT); SetTextColor(dc, CLR_TEXT);
    RECT r1 = { S(10), ROW1_Y(), S(56), ROW1_Y() + S(26) };
    DrawTextW(dc, L"Range:", -1, &r1, DT_SINGLELINE | DT_VCENTER);
    RECT r2 = { S(10), ROW2_Y(), S(56), ROW2_Y() + S(26) };
    DrawTextW(dc, L"Filter:", -1, &r2, DT_SINGLELINE | DT_VCENTER);
}

static void invalidate_tabs(void) {
    RECT rc; GetClientRect(g_wnd, &rc);
    RECT t = { 0, PANEL_H(), TABW(), rc.bottom - STATUS_H() };
    InvalidateRect(g_wnd, &t, FALSE);
}
static void pips_nav_line(HDC dc, int y, int h, const WCHAR *name, const WCHAR *count, int selected, int header, int hot) {
    int w = TABW();
    if (selected) grad(dc, 0, y, w, y+h, RGB(255,236,198),RGB(255,205,136));
    else if (hot) grad(dc,0,y,w,y+h,RGB(250,250,237),RGB(238,240,226));
    else if (header) grad(dc,0,y,w,y+h,RGB(187,213,245),RGB(216,230,249));
    hline(dc,S(7),w-S(7),y+h-1,RGB(185,205,233));
    SetBkMode(dc,TRANSPARENT);
    SelectObject(dc, (header||selected)?g_bold:g_font);
    SetTextColor(dc,selected?RGB(136,76,12):CLR_TEXT);
    RECT title={S(header?10:22),y,w-S(8),y+h};
    DrawTextW(dc,name,-1,&title,DT_SINGLELINE|DT_VCENTER|DT_END_ELLIPSIS);
    if(count && count[0]) { RECT n={0,y,w-S(8),y+h};
        SetTextColor(dc,selected?RGB(160,83,12):RGB(88,126,176));
        DrawTextW(dc,count,-1,&n,DT_SINGLELINE|DT_VCENTER|DT_RIGHT);
    }
}
static void paint_tabs(HDC dc, int top, int bottom) {
    int w = TABW(), th = TABH(), y=top;
    grad(dc, 0, top, w, bottom, RGB(226, 236, 250), RGB(205, 222, 246));
    HPEN pen = CreatePen(PS_SOLID, 1, CLR_BORDER), op = SelectObject(dc, pen);
    MoveToEx(dc, w - 1, top, NULL); LineTo(dc, w - 1, bottom);
    SelectObject(dc, op); DeleteObject(pen);
    WCHAR s[48];
    pips_nav_line(dc,y,th,g_scanner_expanded?L"\x25BE  Scanner":L"\x25B8  Scanner",L"",!g_mon_mode,1,g_tabhot==-2); y+=th;
    if (g_scanner_expanded) for (int i=0;i<6 && y+th<=bottom;i++,y+=th) {
        wsprintfW(s,L"%d",g_tabcount[i]);
        pips_nav_line(dc,y,th,TABNAME[i],s,!g_mon_mode&&g_cat==i,0,g_tabhot==i);
    }
    pips_nav_line(dc,y,th,g_monitor_expanded?L"\x25BE  Monitoring":L"\x25B8  Monitoring",L"",g_mon_mode&&g_mon_subnet<0,1,g_tabhot==-3); y+=th;
    if (g_monitor_expanded) for (int i=0;i<g_nsubnets&&y+S(52)<=bottom;i++,y+=S(52)) {
        int alive=0, dead=0;
        for (int j=0;j<g_nmon;j++) if(!lstrcmpW(g_mon[j].subnet,g_mon_subnets[i])) {
            if(g_mon[j].res.alive)alive++;else dead++;
        }
        int chosen=g_mon_mode&&g_mon_subnet==i;
        if(chosen)grad(dc,0,y,w,y+S(52),RGB(255,239,209),RGB(255,215,159));
        else if(g_tabhot==100+i)grad(dc,0,y,w,y+S(52),RGB(241,249,255),RGB(224,238,255));
        hline(dc,S(8),w-S(8),y+S(51),RGB(174,196,222));
        RECT name={S(24),y+S(3),w-S(8),y+S(24)};
        SetBkMode(dc,TRANSPARENT);SelectObject(dc,g_bold);SetTextColor(dc,chosen?RGB(117,75,23):CLR_TEXT);
        DrawTextW(dc,g_mon_subnets[i],-1,&name,DT_SINGLELINE|DT_VCENTER|DT_END_ELLIPSIS);
        RECT chip1={S(24),y+S(27),S(100),y+S(46)},chip2={S(106),y+S(27),w-S(9),y+S(46)};
        HBRUSH bg=CreateSolidBrush(RGB(220,244,228));FillRect(dc,&chip1,bg);DeleteObject(bg);
        bg=CreateSolidBrush(RGB(255,228,228));FillRect(dc,&chip2,bg);DeleteObject(bg);
        wsprintfW(s,L"\x25CF  Alive %d",alive);SetTextColor(dc,RGB(21,123,65));SelectObject(dc,g_font);
        DrawTextW(dc,s,-1,&chip1,DT_SINGLELINE|DT_CENTER|DT_VCENTER);
        wsprintfW(s,L"\x25CF  Dead %d",dead);SetTextColor(dc,RGB(170,54,54));
        DrawTextW(dc,s,-1,&chip2,DT_SINGLELINE|DT_CENTER|DT_VCENTER);
    }
}
static int tab_hit(int x, int y) {
    RECT rc; GetClientRect(g_wnd, &rc);
    if (x < 0 || x >= TABW() || y < PANEL_H() || y >= rc.bottom - STATUS_H()) return -1;
    int row=y-PANEL_H(), th=TABH();
    if(row<th)return -2;
    row-=th;
    if(g_scanner_expanded){if(row<6*th)return row/th;row-=6*th;}
    if(row<th)return -3;
    row-=th;
    if(g_monitor_expanded&&row<g_nsubnets*S(52))return 100+row/S(52);
    return -1;
}

static void paint_status(HDC dc, int w, int top) {
    int h = STATUS_H();
    grad(dc, 0, top, w, top + h, RGB(221, 236, 254), RGB(196, 218, 250));
    hline(dc, 0, w, top, CLR_BORDER);
    WCHAR b[200];
    LONG dead = g_done - g_alive;
    if (g_msg[0] && (int)(g_msg_until - GetTickCount()) > 0) lstrcpynW(b, g_msg, 200);
    else if (g_running) {
        if (!g_total) lstrcpyW(b, L"Resolving targets...");
        else if (g_debug) wsprintfW(b, L"Scanning (diagnostics on)...   %ld / %ld     Alive: %ld", g_done, g_total, g_alive);
        else wsprintfW(b, L"Scanning...   %ld / %ld     Alive: %ld     Dead: %ld", g_done, g_total, g_alive, dead);
    } else if (g_done)
        wsprintfW(b, L"Done in %lu.%lu s     Scanned: %ld     Alive: %ld     Dead: %ld",
                  g_elapsed / 1000, (g_elapsed % 1000) / 100, g_done, g_alive, dead);
    else if (g_updating) lstrcpyW(b, L"Downloading MAC database from wireshark.org ...");
    else if (g_oui_count) wsprintfW(b, L"Ready.   MAC database: %d entries (updated).   Ranges: 192.168.1.1-254, 10.0.0.0/24, host", g_oui_count);
    else lstrcpyW(b, L"Ready.   Ranges: 192.168.1.1-254, 10.0.0.0/24, 10.0.0.5-10.0.1.20, hostname");
    int show_ping=(g_ping_active || (LONG)(g_ping_until-GetTickCount())>0) && !g_running;
    RECT rc = { show_ping?S(136):S(10), top, w - S(115), top + h };
    SelectObject(dc, g_font); SetBkMode(dc, TRANSPARENT); SetTextColor(dc, CLR_TEXT);
    DrawTextW(dc, b, -1, &rc, DT_SINGLELINE | DT_VCENTER | DT_END_ELLIPSIS);

    if (show_ping) {
        for(int i=0;i<4;i++) {
            COLORREF color=i>=g_ping_count?RGB(164,174,189):
                !g_ping_ok[i]?RGB(217,65,65):g_ping_ms[i]>=100?RGB(232,170,42):RGB(45,168,89);
            HBRUSH br=CreateSolidBrush(color), old=SelectObject(dc,br);
            HPEN pen=CreatePen(PS_SOLID,1,RGB(255,255,255)),op=SelectObject(dc,pen);
            int x=S(12)+i*S(30), y=top+S(8);
            Ellipse(dc,x,y,x+S(13),y+S(13));
            SelectObject(dc,op);DeleteObject(pen);SelectObject(dc,old);DeleteObject(br);
        }
    }

    if (g_running && g_total) {                       /* progress bar */
        RECT pb = { w - S(335), top + S(7), w - S(105), top + h - S(6) };
        HBRUSH wb = CreateSolidBrush(RGB(255, 255, 255)); FillRect(dc, &pb, wb); DeleteObject(wb);
        int fill = MulDiv(pb.right - pb.left - 2, g_done, g_total);
        if (fill > 0) {
            int mid = (pb.top + pb.bottom) / 2;
            grad(dc, pb.left + 1, pb.top + 1, pb.left + 1 + fill, mid, RGB(178, 230, 160), RGB(120, 200, 100));
            grad(dc, pb.left + 1, mid, pb.left + 1 + fill, pb.bottom - 1, RGB(90, 180, 70), RGB(120, 205, 100));
        }
        HBRUSH bb = CreateSolidBrush(CLR_BORDER); FrameRect(dc, &pb, bb); DeleteObject(bb);
    }
}

static void status_dirty(void) {
    RECT rc; GetClientRect(g_wnd, &rc);
    rc.top = rc.bottom - STATUS_H();
    InvalidateRect(g_wnd, &rc, FALSE);
}

static void draw_item_inner(DRAWITEMSTRUCT *d) {
    HDC dc = d->hDC; RECT r = d->rcItem; HWND h = d->hwndItem;
    HBRUSH pbg = CreateSolidBrush(RGB(214, 229, 250));   /* flat panel tone behind the rounded button */
    FillRect(dc, &r, pbg); DeleteObject(pbg);

    int hot = h == g_hot, down = (d->itemState & ODS_SELECTED) != 0, dis = (d->itemState & ODS_DISABLED) != 0;
    WCHAR txt[64]; GetWindowTextW(h, txt, 64);
    SetBkMode(dc, TRANSPARENT);

    if (h == g_chk) {                                     /* check box */
        int bs = S(14), y = (r.bottom - r.top - bs) / 2;
        RECT bx = { r.left + S(2), y, r.left + S(2) + bs, y + bs };
        grad(dc, bx.left, bx.top, bx.right, bx.bottom, RGB(255, 255, 255), RGB(226, 236, 250));
        HBRUSH bb = CreateSolidBrush(hot ? RGB(230, 160, 60) : RGB(110, 145, 200)); FrameRect(dc, &bx, bb); DeleteObject(bb);
        if (g_alive_only) {
            HPEN p = CreatePen(PS_SOLID, S(2), CLR_TEXT), op = SelectObject(dc, p);
            POINT pt[3] = { { bx.left + bs / 5, bx.top + bs / 2 }, { bx.left + bs * 2 / 5, bx.bottom - bs / 4 },
                            { bx.right - bs / 5, bx.top + bs / 4 } };
            Polyline(dc, pt, 3);
            SelectObject(dc, op); DeleteObject(p);
        }
        RECT tr = r; tr.left = bx.right + S(6);
        SelectObject(dc, g_font); SetTextColor(dc, CLR_TEXT);
        DrawTextW(dc, txt, -1, &tr, DT_SINGLELINE | DT_VCENTER);
        if ((d->itemState & ODS_FOCUS) && !(d->itemState & ODS_NOFOCUSRECT)) {
            RECT fr = tr; fr.right = fr.left + S(70); InflateRect(&fr, S(2), -S(5)); DrawFocusRect(dc, &fr);
        }
        return;
    }

    COLORREF t1, t2, b1, b2, bd;
    if (down)       { t1 = RGB(250, 195, 125); t2 = RGB(251, 172, 95);  b1 = RGB(250, 150, 60);  b2 = RGB(253, 200, 120); bd = RGB(194, 118, 43); }
    else if (hot)   { t1 = RGB(255, 251, 226); t2 = RGB(255, 232, 166); b1 = RGB(255, 215, 110); b2 = RGB(255, 236, 170); bd = RGB(219, 169, 79); }
    else            { t1 = RGB(255, 255, 255); t2 = RGB(236, 243, 253); b1 = RGB(214, 229, 250); b2 = RGB(231, 241, 254); bd = CLR_BORDER; }
    HRGN rg = CreateRoundRectRgn(r.left, r.top, r.right + 1, r.bottom + 1, S(6), S(6));
    SelectClipRgn(dc, rg);
    int mid = (r.top + r.bottom) / 2;
    grad(dc, r.left, r.top, r.right, mid, t1, t2);
    grad(dc, r.left, mid, r.right, r.bottom, b1, b2);
    SelectClipRgn(dc, NULL);
    HBRUSH bb = CreateSolidBrush(bd); FrameRgn(dc, rg, bb, 1, 1); DeleteObject(bb); DeleteObject(rg);
    SelectObject(dc, h == g_btn ? g_bold : g_font);
    SetTextColor(dc, dis ? RGB(140, 150, 170) : CLR_TEXT);
    if (down) OffsetRect(&r, 0, 1);
    DrawTextW(dc, txt, -1, &r, DT_SINGLELINE | DT_VCENTER | DT_CENTER);
    if ((d->itemState & ODS_FOCUS) && !(d->itemState & ODS_NOFOCUSRECT)) { InflateRect(&r, -S(3), -S(3)); DrawFocusRect(dc, &r); }
}

static void draw_item(DRAWITEMSTRUCT *d) {
    RECT r = d->rcItem;
    int wdt = r.right - r.left, hgt = r.bottom - r.top;
    if (wdt <= 0 || hgt <= 0) return;
    HDC real = d->hDC, mem = CreateCompatibleDC(real);
    HBITMAP bm = CreateCompatibleBitmap(real, r.right, r.bottom), ob = SelectObject(mem, bm);
    DRAWITEMSTRUCT d2 = *d; d2.hDC = mem;
    draw_item_inner(&d2);
    BitBlt(real, r.left, r.top, wdt, hgt, mem, r.left, r.top, SRCCOPY);
    SelectObject(mem, ob); DeleteObject(bm); DeleteDC(mem);
}

/* hover tracking for the owner-drawn buttons */
static LRESULT CALLBACK btnproc(HWND h, UINT m, WPARAM wp, LPARAM lp) {
    if (m == WM_MOUSEMOVE && g_hot != h) {
        HWND prev = g_hot; g_hot = h;
        TRACKMOUSEEVENT te = { sizeof te, TME_LEAVE, h, 0 }; TrackMouseEvent(&te);
        if (prev) InvalidateRect(prev, NULL, FALSE);
        InvalidateRect(h, NULL, FALSE);
    } else if (m == WM_MOUSELEAVE) {
        g_hot = NULL; InvalidateRect(h, NULL, FALSE);
    } else if (m == WM_LBUTTONDBLCLK) m = WM_LBUTTONDOWN;  /* fast clicks are clicks */
    return CallWindowProcW(g_btnproc, h, m, wp, lp);
}

static HIMAGELIST make_dots(void) {
    int sz = S(16);
    HIMAGELIST il = ImageList_Create(sz, sz, ILC_COLOR32, 2, 0);
    COLORREF col[2] = { RGB(52, 168, 83), RGB(214, 70, 70) };
    for (int k = 0; k < 2; k++) {
        BITMAPINFO bi = {0};
        bi.bmiHeader.biSize = sizeof bi.bmiHeader; bi.bmiHeader.biWidth = sz; bi.bmiHeader.biHeight = -sz;
        bi.bmiHeader.biPlanes = 1; bi.bmiHeader.biBitCount = 32;
        DWORD *px; HBITMAP bm = CreateDIBSection(NULL, &bi, DIB_RGB_COLORS, (void **)&px, NULL, 0);
        int c2 = sz - 1;                  /* centre * 2 */
        int r4 = sz * 9 / 32;             /* radius */
        for (int y = 0; y < sz; y++)
            for (int x = 0; x < sz; x++) {
                int in = 0;               /* 4x4 supersampling, integer math */
                for (int sy = 0; sy < 4; sy++) for (int sx = 0; sx < 4; sx++) {
                    int ex = (x * 8 + sx * 2 + 1) - c2 * 4 - 4, ey = (y * 8 + sy * 2 + 1) - c2 * 4 - 4;
                    if (ex * ex + ey * ey <= r4 * r4 * 64) in++;
                }
                int dy = y * 2 - c2;      /* lighter top half */
                int sh = dy < 0 ? 100 + (-dy * 40) / (sz + 1) : 100;
                int R = GetRValue(col[k]) * sh / 100, G = GetGValue(col[k]) * sh / 100, B = GetBValue(col[k]) * sh / 100;
                if (R > 255) R = 255;
                if (G > 255) G = 255;
                if (B > 255) B = 255;
                int A = in * 255 / 16;
                px[y * sz + x] = ((DWORD)A << 24) | ((DWORD)(R * A / 255) << 16) | ((DWORD)(G * A / 255) << 8) | (DWORD)(B * A / 255);
            }
        ImageList_Add(il, bm, NULL);
        DeleteObject(bm);
    }
    return il;
}

static const WCHAR *col_text(RES *r, int c) {
    switch (c) {
    case C_IP: return r->ips;   case C_NAME: return r->name;  case C_MAC: return r->mac;
    case C_VENDOR: return r->vendor; case C_COMMENT: return r->desc; case C_TYPE: return r->type;
    case C_AUTH: return r->auth; case C_EVENTS: return r->events; case C_PING: return r->ping; case C_MON: return r->monitor;
    case C_PORTS: return r->portsw; default: return r->info;
    }
}

static int CALLBACK cmp(LPARAM a, LPARAM b, LPARAM unused) {
    (void)unused;
    RES *x = (RES *)a, *y = (RES *)b; int d;
    int ipd = x->ip < y->ip ? -1 : x->ip > y->ip;
    if (g_sortcol == C_IP) d = ipd;
    else if (g_sortcol == C_PING) {
        if ((x->rtt < 0) != (y->rtt < 0)) return x->rtt < 0 ? 1 : -1;
        d = x->rtt - y->rtt; if (!d) d = ipd;
    } else if (g_sortcol == C_MON) {
        if (!x->monitor[0] != !y->monitor[0]) return x->monitor[0] ? -1 : 1;
        d=_wtoi(x->monitor)-_wtoi(y->monitor);if(!d)d=ipd;
    } else {
        const WCHAR *s = col_text(x, g_sortcol), *t = col_text(y, g_sortcol);
        if (!*s != !*t) return *s ? -1 : 1;              /* empty cells always last */
        d = lstrcmpiW(s, t); if (!d) d = ipd;
    }
    return d * g_sortdir;
}

static void insert_row(RES *r) {
    LVITEMW it = {0};
    it.mask = LVIF_TEXT | LVIF_PARAM | LVIF_IMAGE; it.iItem = 0x7FFFFFFF;
    it.lParam = (LPARAM)r; it.pszText = r->ips; it.iImage = r->alive ? 0 : 1;
    int i = (int)SendMessageW(g_list, LVM_INSERTITEMW, 0, (LPARAM)&it);
    for (int c = 1; c < NCOLS; c++) {
        const WCHAR *t = col_text(r, c);
        if (!*t) continue;
        LVITEMW s = {0}; s.iSubItem = c; s.pszText = (WCHAR *)t;
        SendMessageW(g_list, LVM_SETITEMTEXTW, i, (LPARAM)&s);
    }
}

static int wci_sub(const WCHAR *hay, const WCHAR *ned) {   /* case-insensitive substring */
    if (!*ned) return 1;
    for (; *hay; hay++) {
        const WCHAR *a = hay, *b = ned;
        for (;;) {
            WCHAR ca = *a, cb = *b;
            if (!cb) return 1;
            if (ca >= 'A' && ca <= 'Z') ca += 32;
            if (cb >= 'A' && cb <= 'Z') cb += 32;
            if (ca != cb) break;
            a++; b++;
        }
    }
    return 0;
}
static int cat_of(RES *r) {                 /* 1 NVR, 2 IP cam, 3 PC, 5 Other */
    if (wci_sub(r->type, L"nvr") || wci_sub(r->type, L"dvr")) return 1;
    if (!lstrcmpiW(r->type, L"IP camera")) return 2;
    if (wci_sub(r->type, L"windows") || wci_sub(r->type, L"linux pc") ||
        !lstrcmpiW(r->type, L"PC") || wci_sub(r->type, L"domain controller")) return 3;
    return 5;
}
static int in_cat(RES *r) {
    switch (g_cat) {
    case 1: return cat_of(r) == 1;
    case 2: return cat_of(r) == 2;
    case 3: return cat_of(r) == 3;
    case 4: return (r->ports & pbit(3389)) != 0;
    case 5: return cat_of(r) == 5;
    default: return 1;
    }
}
static int row_visible(RES *r) {
    if (!in_cat(r)) return 0;
    if (!g_filter[0]) return 1;
    for (int c = 0; c < NCOLS; c++) if (wci_sub(col_text(r, c), g_filter)) return 1;
    return 0;
}
static void recount_tabs(void) {
    for (int i = 0; i < 6; i++) g_tabcount[i] = 0;
    for (int i = 0; i < g_nres; i++) {
        RES *r = g_res[i];
        if (!r->alive && g_alive_only) continue;
        g_tabcount[0]++;
        int c = cat_of(r);
        g_tabcount[c == 1 ? 1 : c == 2 ? 2 : c == 3 ? 3 : 5]++;
        if (r->ports & pbit(3389)) g_tabcount[4]++;
    }
}

static void refill(void) {
    SendMessageW(g_list, WM_SETREDRAW, FALSE, 0);
    SendMessageW(g_list, LVM_DELETEALLITEMS, 0, 0);
    if (g_mon_mode) {
        for (int i=0;i<g_nmon;i++) {
            PipsMon *m=&g_mon[i];
            if (g_mon_subnet>=0 && (g_mon_subnet>=g_nsubnets || lstrcmpW(m->subnet,g_mon_subnets[g_mon_subnet]))) continue;
            if (!g_filter[0]) insert_row(&m->res);
            else for (int c=0;c<NCOLS;c++) if (wci_sub(col_text(&m->res,c),g_filter)) { insert_row(&m->res); break; }
        }
    } else {
        for (int i = 0; i < g_nres; i++) if ((g_res[i]->alive || !g_alive_only) && row_visible(g_res[i])) insert_row(g_res[i]);
    }
    SendMessageW(g_list, LVM_SORTITEMS, 0, (LPARAM)cmp);
    SendMessageW(g_list, WM_SETREDRAW, TRUE, 0);
    InvalidateRect(g_list, NULL, TRUE);
    recount_tabs(); invalidate_tabs();
}

/* ---------- manual type overrides, kept in ipscan.ini (next to the exe, else %APPDATA%) ---------- */
static void ini_init(void) {
    DWORD n = GetModuleFileNameW(NULL, g_ini, MAX_PATH - 5);
    while (n && g_ini[n - 1] != '.' && g_ini[n - 1] != '\\') n--;
    if (n && g_ini[n - 1] == '.') lstrcpyW(g_ini + n, L"ini"); else lstrcatW(g_ini, L".ini");
    ExpandEnvironmentStringsW(L"%APPDATA%\\ipscan.ini", g_ini2, MAX_PATH);
}
static const WCHAR *row_key(RES *r) { return r->mac[0] ? r->mac : r->ips; }
static int ini_get(const WCHAR *key, WCHAR *out) {
    if (GetPrivateProfileStringW(L"types", key, L"", out, 24, g_ini)) return 1;
    return GetPrivateProfileStringW(L"types", key, L"", out, 24, g_ini2) > 0;
}
static void ini_set(const WCHAR *key, const WCHAR *val) {   /* val NULL = remove */
    if (!val) {
        if (GetFileAttributesW(g_ini) != INVALID_FILE_ATTRIBUTES) WritePrivateProfileStringW(L"types", key, NULL, g_ini);
        if (GetFileAttributesW(g_ini2) != INVALID_FILE_ATTRIBUTES) WritePrivateProfileStringW(L"types", key, NULL, g_ini2);
        return;
    }
    if (!WritePrivateProfileStringW(L"types", key, val, g_ini)) WritePrivateProfileStringW(L"types", key, val, g_ini2);
}

static int ini_read(const WCHAR *sec, const WCHAR *key, WCHAR *out, int cap);
static void invalidate_tabs(void);
static void recount_tabs(void);
static void ini_put(const WCHAR *sec, const WCHAR *key, const WCHAR *val);

static void update_history(RES *r, const WCHAR *key) {
    SYSTEMTIME st; GetLocalTime(&st);
    WCHAR now[20]; wsprintfW(now, L"%02d-%02d %02d:%02d", st.wMonth, st.wDay, st.wHour, st.wMinute);
    WCHAR seen[160] = L"", oldev[220] = L"";
    ini_read(L"seen", key, seen, 160);
    ini_read(L"events", key, oldev, 220);
    WCHAR parts[3][96]; int np = 0;
    WCHAR *tab = wchr(seen, '\t'); const WCHAR *oldname = L"";
    if (tab) { *tab = 0; oldname = tab + 1; }
    if (seen[0] && lstrcmpW(seen, r->ips) && np < 3) wsprintfW(parts[np++], L"IP %s\u2192%s %s", seen, r->ips, now);
    if (r->name[0] && oldname[0] && lstrcmpW(oldname, r->name) && np < 3) wsprintfW(parts[np++], L"Name \u2018%s\u2019 %s", r->name, now);
    if (np < 3) wsprintfW(parts[np++], L"Active %s", now);
    WCHAR *q = oldev;                                   /* keep older non-Active events */
    while (np < 3 && *q) {
        while (*q == ' ') q++;
        WCHAR *bgn = q; while (*q && *q != 0x00B7) q++;
        WCHAR *end = q; if (*q) q++;
        while (end > bgn && end[-1] == ' ') end--;
        int len = (int)(end - bgn);
        if (len > 0 && len < 95) {
            WCHAR tok[96]; lstrcpynW(tok, bgn, len + 1);
            if (!(tok[0] == 'A' && tok[1] == 'c' && tok[2] == 't' && tok[3] == 'i')) lstrcpyW(parts[np++], tok);
        }
    }
    WCHAR out[260] = L"";
    for (int i = 0; i < np; i++) { if (i) lstrcatW(out, L" \u00b7 "); lstrcatW(out, parts[i]); }
    lstrcpynW(r->events, out, 160);
    ini_put(L"events", key, out[0] ? out : NULL);
    WCHAR sv[160]; wsprintfW(sv, L"%s\t%s", r->ips, r->name);
    ini_put(L"seen", key, sv);
}

static void add_result(RES *r) {
    if (g_nres >= g_capres) {
        g_capres = g_capres ? g_capres * 2 : 256;
        g_res = (RES **)xrealloc(g_res, g_capres * sizeof(RES *));
    }
    g_res[g_nres++] = r;
    WCHAR o[128];
    const WCHAR *key = row_key(r);
    int manual = r->alive && ini_get(key, o);
    if (manual) lstrcpyW(r->type, o);                       /* user override wins */
    else if (r->alive) {
        if (r->confident) {                                 /* remember a solid auto-detection */
            WCHAR prev[32]; int had = ini_read(L"known", key, prev, 32);
            int prev_nvr = had && (wci_sub(prev, L"nvr") || wci_sub(prev, L"dvr"));
            int now_nvr = wci_sub(r->autotype, L"nvr") || wci_sub(r->autotype, L"dvr");
            if (!had || (now_nvr && !prev_nvr)) {           /* first verdict, or an upgrade to NVR */
                ini_put(L"known", key, r->autotype);
                if (r->autodev[0]) ini_put(L"knowndev", key, r->autodev);
            } else if (prev_nvr && !now_nvr) {              /* keep the recorder verdict sticky */
                lstrcpynW(r->type, prev, 24); lstrcpyW(r->autotype, r->type);
            }
        } else {                                            /* reuse what a past scan established */
            if (ini_read(L"known", key, o, 128)) { lstrcpynW(r->type, o, 24); lstrcpyW(r->autotype, r->type); }
            if (!r->autodev[0] && ini_read(L"knowndev", key, o, 96)) {
                WCHAR merged[240];
                lstrcpynW(merged, o, 96);
                if (r->info[0]) { lstrcatW(merged, L",  "); int l = lstrlenW(merged); lstrcpynW(merged + l, r->info, 240 - l); }
                lstrcpynW(r->info, merged, 240);
                lstrcpynW(r->autodev, o, 96);
            }
        }
    }
    if (r->alive && ini_read(L"desc", key, o, 128)) lstrcpynW(r->desc, o, 128);
    if (r->alive && ini_read(L"auth", key, o, 40)) lstrcpynW(r->auth, o, 40);
    for(int i=0;i<g_nmon;i++)if(g_mon[i].res.ip==r->ip){wsprintfW(r->monitor,L"%d sec",g_mon[i].interval);break;}
    if (r->alive) update_history(r, key);
    pips_device_store(r);
    for (int i=0;i<g_nmon;i++) if (g_mon[i].res.ip == r->ip && r->alive) {
        int status=g_mon[i].res.alive, interval=g_mon[i].interval, pending=g_mon[i].pending;
        WCHAR oldping[10]; lstrcpynW(oldping,g_mon[i].res.ping,10);
        g_mon[i].res=*r; g_mon[i].res.alive=status; g_mon[i].interval=interval;g_mon[i].pending=pending;
        lstrcpynW(g_mon[i].res.ping,oldping,10);
        break;
    }
    if (!g_mon_mode && (r->alive || !g_alive_only) && row_visible(r)) insert_row(r);
    recount_tabs(); invalidate_tabs();
}

static void clear_results(void) {
    if(!g_mon_mode)SendMessageW(g_list, LVM_DELETEALLITEMS, 0, 0);
    for (int i = 0; i < g_nres; i++) xfree(g_res[i]);
    g_nres = 0;
}

static RES *row_res(int i) {
    LVITEMW it = {0}; it.mask = LVIF_PARAM; it.iItem = i;
    SendMessageW(g_list, LVM_GETITEMW, 0, (LPARAM)&it);
    return (RES *)it.lParam;
}

/* A right-click command must keep operating on the original multi-selection,
   even if the operation rebuilds the list or shifts monitoring records. */
static RES *selected_snapshot(int *count) {
    *count=(int)SendMessageW(g_list,LVM_GETSELECTEDCOUNT,0,0);
    if(*count<=0)return NULL;
    RES *rows=xalloc((size_t)*count*sizeof *rows);
    if(!rows){*count=0;return NULL;}
    int n=0;
    for(int i=-1;(i=(int)SendMessageW(g_list,LVM_GETNEXTITEM,i,LVNI_SELECTED))>=0 && n<*count;)
        rows[n++]=*row_res(i);
    *count=n;return rows;
}
static int confirm_multi_launch(int count,const WCHAR *action) {
    if(count<=1)return 1;
    WCHAR msg[220];
    wsprintfW(msg,L"%s on %d selected devices?\n\nThis can open several windows or connections.",action,count);
    return MessageBoxW(g_wnd,msg,L"PIPS Scanner - Multiple devices",MB_ICONQUESTION|MB_YESNO)==IDYES;
}
static void monitoring_selected(int interval,int removing) {
    int n=0;RES *rows=selected_snapshot(&n);if(!rows)return;
    g_mon_batch=1;
    for(int i=0;i<n;i++) {
        if(removing)pips_monitor_remove(&rows[i]);
        else pips_monitor_add(&rows[i],interval);
    }
    g_mon_batch=0;
    xfree(rows);refill();
}

static void clip(const WCHAR *s) {
    if (!OpenClipboard(g_wnd)) return;
    EmptyClipboard();
    size_t n = (lstrlenW(s) + 1) * sizeof(WCHAR);
    HGLOBAL h = GlobalAlloc(GMEM_MOVEABLE, n);
    if (h) { memcpy(GlobalLock(h), s, n); GlobalUnlock(h); SetClipboardData(CF_UNICODETEXT, h); }
    CloseClipboard();
}

/* col >= 0: that column of every selected row; col < 0: whole rows, tab separated */
static void copy_sel(int col) {
    int n = (int)SendMessageW(g_list, LVM_GETSELECTEDCOUNT, 0, 0);
    if (!n) return;
    WCHAR *buf = (WCHAR *)xalloc(((size_t)n * 1400 + 1) * sizeof(WCHAR)), *p = buf;
    if(!buf)return;
    for (int i = -1; (i = (int)SendMessageW(g_list, LVM_GETNEXTITEM, i, LVNI_SELECTED)) >= 0;) {
        RES *r = row_res(i);
        if (col >= 0) { lstrcpyW(p, col_text(r, col)); p += lstrlenW(p); }
        else for (int c = 0; c < NCOLS; c++) {
            lstrcpyW(p, col_text(r, c)); p += lstrlenW(p);
            if (c < NCOLS - 1) *p++ = '\t';
        }
        if (n > 1) { *p++ = '\r'; *p++ = '\n'; }
    }
    *p = 0;
    clip(buf); xfree(buf);
}

static void csv_field(HANDLE f, const WCHAR *s, int last) {
    char u[400]; DWORD w; int n = 1;
    u[0] = '"';
    for (; *s && n < 380; s++) {
        if (*s == '"') u[n++] = '"';
        n += WideCharToMultiByte(CP_UTF8, 0, s, 1, u + n, 8, NULL, NULL);
    }
    u[n++] = '"'; u[n++] = last ? '\n' : ',';
    WriteFile(f, u, n, &w, NULL);
}

static void export_csv(void) {
    WCHAR fn[MAX_PATH] = L"scan.csv";
    OPENFILENAMEW of = {0};
    of.lStructSize = sizeof of; of.hwndOwner = g_wnd; of.lpstrFile = fn; of.nMaxFile = MAX_PATH;
    of.lpstrFilter = L"CSV (*.csv)\0*.csv\0All files\0*.*\0"; of.lpstrDefExt = L"csv";
    of.Flags = OFN_OVERWRITEPROMPT | OFN_PATHMUSTEXIST;
    if (!GetSaveFileNameW(&of)) return;
    HANDLE f = CreateFileW(fn, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
    if (f == INVALID_HANDLE_VALUE) { MessageBoxW(g_wnd, L"Cannot write file.", L"Export", MB_ICONERROR); return; }
    DWORD w; WriteFile(f, "\xEF\xBB\xBF", 3, &w, NULL);
    csv_field(f, L"Status", 0);
    for (int c = 0; c < NCOLS; c++) csv_field(f, COLNAME[c], c == NCOLS - 1);
    int n = (int)SendMessageW(g_list, LVM_GETITEMCOUNT, 0, 0);
    for (int i = 0; i < n; i++) {
        RES *r = row_res(i);
        csv_field(f, r->alive ? L"alive" : L"dead", 0);
        for (int c = 0; c < NCOLS; c++) csv_field(f, col_text(r, c), c == NCOLS - 1);
    }
    CloseHandle(f);
}

/* register this exe for IE11 rendering + ActiveX so NVR/camera plug-ins load */
static void ie_feature_setup(void) {
    WCHAR exe[MAX_PATH]; GetModuleFileNameW(NULL, exe, MAX_PATH);
    WCHAR *base = exe; for (WCHAR *q = exe; *q; q++) if (*q == '\\') base = q + 1;
    HKEY k;
    if (RegCreateKeyExW(HKEY_CURRENT_USER,
        L"Software\\Microsoft\\Internet Explorer\\Main\\FeatureControl\\FEATURE_BROWSER_EMULATION",
        0, NULL, 0, KEY_SET_VALUE, NULL, &k, NULL) == ERROR_SUCCESS) {
        DWORD v = 11000; RegSetValueExW(k, base, 0, REG_DWORD, (const BYTE *)&v, sizeof v); RegCloseKey(k);
    }
}

static void set_msg(const WCHAR *m);
static void share_open2(DWORD ip, const PROF *pr);
static const PROF *prof_by_label(const WCHAR *label);
/* Open the viewer in a SEPARATE process, so a crashing camera ActiveX plug-in cannot take
   the scanner down with it. Prefer the 32-bit ipscan.exe (32-bit ActiveX); on a 32-bit build
   fall back to spawning ourselves. Credentials go through the environment, not the command line. */
static void open_view_ips(const WCHAR *ips, const WCHAR *user, const WCHAR *pass, int modern) {
    WCHAR dir[MAX_PATH]; DWORD n = GetModuleFileNameW(NULL, dir, MAX_PATH - 24);
    while (n && dir[n - 1] != '\\') n--;
    dir[n] = 0;
    static const WCHAR *names[] = { L"PIPS-Scanner.exe", L"ipscan.exe", L"ipscan-x86.exe" };
    WCHAR exe[MAX_PATH]; int found = 0;
    for (int k = 0; k < 3 && !found; k++) { wsprintfW(exe, L"%s%s", dir, names[k]); if (GetFileAttributesW(exe) != INVALID_FILE_ATTRIBUTES) found = 1; }
#ifndef _WIN64
    if (!found) { GetModuleFileNameW(NULL, exe, MAX_PATH); found = 1; }   /* 32-bit: spawn self */
#endif
    if (!found) {
        static int warned;
        if (!warned++) MessageBoxW(g_wnd, L"Put the 32-bit PIPS-Scanner.exe in this folder: the camera viewer runs as a "
            L"separate 32-bit process so a plug-in crash can't close the scanner.", L"Viewer", MB_ICONINFORMATION);
        return;
    }
    WCHAR command[MAX_PATH+96];wsprintfW(command,L"\"%s\" --view %s",exe,ips);
    if (user && user[0]) { SetEnvironmentVariableW(L"IPSCAN_VU", user); SetEnvironmentVariableW(L"IPSCAN_VP", pass ? pass : L""); }
    if (modern) SetEnvironmentVariableW(L"IPSCAN_MODERN", L"1");
    /* CreateProcess completes the environment handoff before returning.
       ShellExecute can defer launch until after temporary secrets are cleared. */
    STARTUPINFOW si={0};si.cb=sizeof si;PROCESS_INFORMATION pi={0};
    BOOL launched=CreateProcessW(exe,command,NULL,NULL,FALSE,0,NULL,dir,&si,&pi);
    if(launched){CloseHandle(pi.hThread);CloseHandle(pi.hProcess);}
    if (modern) SetEnvironmentVariableW(L"IPSCAN_MODERN", NULL);
    if (user && user[0]) { SetEnvironmentVariableW(L"IPSCAN_VU", NULL); SetEnvironmentVariableW(L"IPSCAN_VP", NULL); }
    if(!launched)MessageBoxW(g_wnd,L"Could not launch the separate camera viewer process.",L"PIPS Viewer",MB_ICONWARNING);
}
static void open_viewer_sel(void) {
    int i = (int)SendMessageW(g_list, LVM_GETNEXTITEM, (WPARAM)-1, LVNI_FOCUSED | LVNI_SELECTED);
    if (i < 0) i = (int)SendMessageW(g_list, LVM_GETNEXTITEM, (WPARAM)-1, LVNI_SELECTED);
    if (i < 0) return;
    RES *r = row_res(i);
    if(r->alive){
        const PROF *pr=prof_by_label(r->auth);
        if(pr&&pr->proto==P_CAM)open_view_ips(r->ips,pr->user,pr->pass,0);
        else open_view_ips(r->ips,L"",L"",cat_of(r)!=1&&cat_of(r)!=2);
    }
}
static void open_viewer_selected(void) {
    int n=0;RES *rows=selected_snapshot(&n);if(!rows)return;
    if(confirm_multi_launch(n,L"Open viewer"))for(int i=0;i<n;i++)if(rows[i].alive){
        const PROF *pr=prof_by_label(rows[i].auth);
        if(pr&&pr->proto==P_CAM)open_view_ips(rows[i].ips,pr->user,pr->pass,0);
        else open_view_ips(rows[i].ips,L"",L"",cat_of(&rows[i])!=1&&cat_of(&rows[i])!=2);
    }
    xfree(rows);
}

/* ---- apply a credential profile to a device (per protocol) ---- */
#define CM_PROFBASE 600
static void remember_auth(DWORD ip, const WCHAR *label) {
    WCHAR w[16]; ip2w(ip, w);
    const WCHAR *key=w;
    for(int i=0;i<g_nmon;i++)if(g_mon[i].res.ip==ip){
        lstrcpynW(g_mon[i].res.auth,label,40);
        key=row_key(&g_mon[i].res);
    }
    for(int i=0;i<g_nres;i++)if(g_res[i]->ip==ip){
        lstrcpynW(g_res[i]->auth,label,40);
        key=row_key(g_res[i]);
    }
    ini_put(L"auth",key,label[0]?label:NULL);
    if(g_list)for(int k=0,n=(int)SendMessageW(g_list,LVM_GETITEMCOUNT,0,0);k<n;k++){
        RES *r=row_res(k);
        if(r&&r->ip==ip){
            lstrcpynW(r->auth,label,40);
            LVITEMW s={0};s.iSubItem=C_AUTH;s.pszText=r->auth;
            SendMessageW(g_list,LVM_SETITEMTEXTW,k,(LPARAM)&s);
        }
    }
}
static void apply_profile(RES *r, const PROF *pr) {
    DWORD ip; if (!parse_ip(r->ips, &ip)) return;
    WCHAR a[600];
    switch (pr->proto) {
    case P_FS: share_open2(ip, pr); break;                 /* remembered on success */
    case P_RDP:
        wsprintfW(a, L"/c cmdkey /generic:TERMSRV/%s /user:%s /pass:%s >nul 2>&1", r->ips, pr->user, pr->pass);
        ShellExecuteW(g_wnd, NULL, L"cmd.exe", a, NULL, SW_HIDE);
        wsprintfW(a, L"/v:%s", r->ips);
        ShellExecuteW(g_wnd, NULL, L"mstsc.exe", a, NULL, SW_SHOW);
        remember_auth(ip, pr->label);
        break;
    case P_SSH:
        wsprintfW(a, L"/k ssh %s@%s", pr->user, r->ips);
        ShellExecuteW(g_wnd, NULL, L"cmd.exe", a, NULL, SW_SHOW);
        remember_auth(ip, pr->label);
        break;
    case P_CAM: {
        WCHAR m[160];
        wsprintfW(m, L"Viewer %s  -  %s:  auto-filling login (user '%s').", r->ips, pr->label, pr->user);
        set_msg(m);
        open_view_ips(r->ips, pr->user, pr->pass, 0);
        remember_auth(ip, pr->label);
        break;
    }
    }
}
static const PROF *prof_by_label(const WCHAR *label) {
    if (!label[0]) return NULL;
    for (int i = 0; i < g_nprof; i++) if (!lstrcmpW(g_prof[i].label, label)) return &g_prof[i];
    return NULL;
}

/* transient status message (auto-clears) */
static void set_msg(const WCHAR *m) {
    lstrcpynW(g_msg, m, 160);
    g_msg_until = GetTickCount() + 6000;
    status_dirty();
}

enum { SH_OPEN = 1, SH_PROMPT, SH_NOSMB, SH_FAIL };
typedef struct { DWORD ip; int code; DWORD err; WCHAR label[40]; } SHRES;
typedef struct { DWORD ip; int hascreds; WCHAR user[64], pass[64], label[40]; } SHREQ;
static void remember_auth(DWORD ip, const WCHAR *label);

/* non-blocking TCP check: is this port reachable within ms? */
static int port_open(DWORD nip, u_short port, int ms) {
    SOCKET k = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (k == INVALID_SOCKET) return 0;
    u_long nb = 1; ioctlsocket(k, FIONBIO, &nb);
    struct sockaddr_in sa; memset(&sa, 0, sizeof sa);
    sa.sin_family = AF_INET; sa.sin_port = htons(port); sa.sin_addr.s_addr = nip;
    connect(k, (struct sockaddr *)&sa, sizeof sa);
    fd_set wf, ef; FD_ZERO(&wf); FD_ZERO(&ef); FD_SET(k, &wf); FD_SET(k, &ef);
    struct timeval tv; tv.tv_sec = ms / 1000; tv.tv_usec = (ms % 1000) * 1000;
    int ok = 0;
    if (select(0, NULL, &wf, &ef, &tv) > 0 && FD_ISSET(k, &wf)) {
        int err = 0, len = sizeof err;
        getsockopt(k, SOL_SOCKET, SO_ERROR, (char *)&err, &len);
        ok = (err == 0);
    }
    closesocket(k);
    return ok;
}

static void share_post(const SHREQ *q, int code, DWORD err) {
    SHRES *h = (SHRES *)xalloc(sizeof *h);
    h->ip = q->ip; h->code = code; h->err = err; lstrcpyW(h->label, q->label);
    if (!PostMessageW(g_wnd, WM_SHARE, 0, (LPARAM)h)) xfree(h);
}

static DWORD WINAPI share_thread(LPVOID p) {
    SHREQ *q = (SHREQ *)p; DWORD nip = htonl(q->ip);
    if (!port_open(nip, 445, 1200) && !port_open(nip, 139, 1200)) {   /* fast SMB reachability */
        share_post(q, SH_NOSMB, 0);
        wipe(q, sizeof *q); xfree(q); InterlockedDecrement(&g_share_busy); return 0;
    }
    WCHAR unc[32]; wsprintfW(unc, L"\\\\%u.%u.%u.%u", q->ip >> 24, (q->ip >> 16) & 255, (q->ip >> 8) & 255, q->ip & 255);
    NETRESOURCEW nr; memset(&nr, 0, sizeof nr);
    nr.dwType = RESOURCETYPE_DISK; nr.lpRemoteName = unc;
    DWORD rc = q->hascreds ? WNetAddConnection2W(&nr, q->pass, q->user, 0)
                           : WNetAddConnection2W(&nr, NULL, NULL, 0);   /* passthrough when no profile */
    if (rc == NO_ERROR || rc == ERROR_ALREADY_ASSIGNED || rc == ERROR_DEVICE_ALREADY_REMEMBERED)
        share_post(q, SH_OPEN, 0);
    else if (!q->hascreds && rc!=ERROR_BAD_NETPATH && rc!=ERROR_NETWORK_UNREACHABLE &&
             rc!=ERROR_HOST_UNREACHABLE && rc!=ERROR_NO_NETWORK && rc!=ERROR_BAD_NET_NAME)
        share_post(q,SH_PROMPT,rc);
    else
        share_post(q, SH_FAIL, rc);
    wipe(q, sizeof *q); xfree(q);
    InterlockedDecrement(&g_share_busy);
    return 0;
}

static void share_open2(DWORD ip, const PROF *pr) {
    SHREQ *q = (SHREQ *)xalloc(sizeof *q);
    q->ip = ip;
    if (pr) { q->hascreds = 1; lstrcpyW(q->user, pr->user); lstrcpyW(q->pass, pr->pass); lstrcpyW(q->label, pr->label); }
    WCHAR m[96];
    if (pr) wsprintfW(m, L"Connecting to \\\\%u.%u.%u.%u as %s ...", ip >> 24, (ip >> 16) & 255, (ip >> 8) & 255, ip & 255, pr->label);
    else    wsprintfW(m, L"Connecting to \\\\%u.%u.%u.%u ...", ip >> 24, (ip >> 16) & 255, (ip >> 8) & 255, ip & 255);
    set_msg(m);
    InterlockedIncrement(&g_share_busy);
    HANDLE h = CreateThread(NULL, 0, share_thread, q, 0, NULL);
    if (h) CloseHandle(h); else { xfree(q); InterlockedDecrement(&g_share_busy); }
}
static void share_open(DWORD ip) { share_open2(ip, NULL); }

/* Windows credentials prompt, used explicitly from the menu or when the
   current user's SMB connection fails. Passwords remain transient in RAM. */
static void share_prompt_credentials(DWORD ip) {
    WCHAR target[32],user[64]=L"",pass[64]=L"",message[180];
    wsprintfW(target,L"\\\\%u.%u.%u.%u",ip>>24,(ip>>16)&255,(ip>>8)&255,ip&255);
    wsprintfW(message,L"Sign in to %s with a different account.\nUse COMPUTER\\username or DOMAIN\\username if required.",target);
    CREDUI_INFOW ui={0};ui.cbSize=sizeof ui;ui.hwndParent=g_wnd;
    ui.pszCaptionText=L"PIPS Scanner - Network shares";ui.pszMessageText=message;
    BOOL save=FALSE;
    DWORD result=CredUIPromptForCredentialsW(&ui,target,NULL,0,user,64,pass,64,&save,
        CREDUI_FLAGS_GENERIC_CREDENTIALS|CREDUI_FLAGS_ALWAYS_SHOW_UI|CREDUI_FLAGS_DO_NOT_PERSIST);
    if(result==NO_ERROR){
        PROF pr={0};pr.proto=P_FS;
        lstrcpynW(pr.user,user,64);lstrcpynW(pr.pass,pass,64);
        share_open2(ip,&pr);
        wipe(&pr,sizeof pr);
    } else if(result==ERROR_CANCELLED)set_msg(L"Network login cancelled.");
    else set_msg(L"Could not display the network login prompt.");
    wipe(user,sizeof user);wipe(pass,sizeof pass);
}

/* runs on the UI thread when a background share attempt reports back */
static void share_result(SHRES *h) {
    WCHAR unc[32], m[160];
    wsprintfW(unc, L"\\\\%u.%u.%u.%u", h->ip >> 24, (h->ip >> 16) & 255, (h->ip >> 8) & 255, h->ip & 255);
    switch (h->code) {
    case SH_OPEN:
        ShellExecuteW(g_wnd, L"open", unc, NULL, NULL, SW_SHOW);
        if (h->label[0]) { remember_auth(h->ip, h->label); wsprintfW(m, L"%s  opened as %s.", unc, h->label); }
        else wsprintfW(m, L"%s  opened.", unc);
        set_msg(m);
        break;
    case SH_PROMPT: {
        share_prompt_credentials(h->ip);
        break;
    }
    case SH_NOSMB:
        wsprintfW(m, L"%s  -  file / printer sharing is off or blocked (SMB 445 / 139 closed).", unc);
        set_msg(m);
        break;
    default:
        if(h->err==ERROR_SESSION_CREDENTIAL_CONFLICT)
            wsprintfW(m,L"%s - Windows already has a connection using another account (1219). Disconnect it before switching.",unc);
        else wsprintfW(m, L"%s  -  cannot connect (error %lu).", unc, h->err);
        set_msg(m);
        break;
    }
    xfree(h);
}

static DWORD WINAPI ping_thread(LPVOID p) {
    PipsPingDot *job=(PipsPingDot*)p;
    DWORD ip=job->ip, generation=job->generation, nip=htonl(ip);
    xfree(job);
    HANDLE icmp = IcmpCreateFile();
    int got = 0, best = 0, sum = 0;
    if (icmp != INVALID_HANDLE_VALUE) {
        char data[16] = "ipscan-ping";
        BYTE rep[sizeof(ICMP_ECHO_REPLY) + 64];
        for (int i = 0; i < 4; i++) {
            DWORD started=GetTickCount(), elapsed;
            int ok=0, measured=-1;
            if (IcmpSendEcho(icmp, nip, data, sizeof data, NULL, rep, sizeof rep, 1000)) {
                ICMP_ECHO_REPLY *e = (ICMP_ECHO_REPLY *)rep;
                if (e->Status == IP_SUCCESS) { int rt = (int)e->RoundTripTime; got++; sum += rt; if (!best || rt < best) best = rt;ok=1;measured=rt; }
            }
            PipsPingDot *dot=xalloc(sizeof *dot);
            if(dot){dot->ip=ip;dot->generation=generation;dot->seq=i;dot->ok=ok;dot->rtt=measured;
                if(!PostMessageW(g_wnd,WM_PINGDOT,0,(LPARAM)dot))xfree(dot);
            }
            elapsed=GetTickCount()-started;
            if(i<3 && elapsed<1000)Sleep(1000-elapsed);
        }
        IcmpCloseHandle(icmp);
    }
    WCHAR *m = (WCHAR *)xalloc(160 * sizeof(WCHAR));
    if (got) wsprintfW(m, L"Ping %u.%u.%u.%u :  %d/4 replies, avg %d ms (min %d ms)",
                       ip >> 24, (ip >> 16) & 255, (ip >> 8) & 255, ip & 255, got, sum / got, best);
    else wsprintfW(m, L"Ping %u.%u.%u.%u :  no reply (0/4) - host down or blocking ICMP",
                   ip >> 24, (ip >> 16) & 255, (ip >> 8) & 255, ip & 255);
    if (!PostMessageW(g_wnd, WM_PINGMSG, 0, (LPARAM)m)) xfree(m);
    return 0;
}

static void ping_res(RES *r) {
    DWORD ip;
    if (!parse_ip(r->ips, &ip)) return;
    WCHAR m[64]; wsprintfW(m, L"Pinging %s ...", r->ips); set_msg(m);
    PipsPingDot *job=xalloc(sizeof *job); if(!job)return;
    job->ip=ip;job->generation=(DWORD)InterlockedIncrement(&g_ping_generation);
    g_ping_count=0;g_ping_active=1;g_ping_until=GetTickCount()+18000;
    lstrcpynW(g_ping_ip,r->ips,16);
    HANDLE h = CreateThread(NULL, 0, ping_thread, job, 0, NULL);
    if (h) CloseHandle(h);
    else {g_ping_active=0;xfree(job);}
}
static void ping_sel(void) {
    int n=0;RES *rows=selected_snapshot(&n);if(!rows)return;
    if(confirm_multi_launch(n,L"Ping"))for(int i=0;i<n;i++)ping_res(&rows[i]);
    xfree(rows);
}

static void open_target_one(RES *r,int cmd) {
    WCHAR a[300];
    switch (cmd) {
    case CM_HTTP:  wsprintfW(a, L"http://%s/", r->ips);  ShellExecuteW(g_wnd, L"open", a, NULL, NULL, SW_SHOW); break;
    case CM_HTTPS: wsprintfW(a, L"https://%s/", r->ips); ShellExecuteW(g_wnd, L"open", a, NULL, NULL, SW_SHOW); break;
    case CM_SMB: { DWORD ip; if (parse_ip(r->ips, &ip)) share_open(ip); break; }
    case CM_SMB_OTHER: { DWORD ip; if(parse_ip(r->ips,&ip))share_prompt_credentials(ip); break; }
    case CM_RDP:   wsprintfW(a, L"/v:%s", r->ips); ShellExecuteW(g_wnd, NULL, L"mstsc.exe", a, NULL, SW_SHOW); break;
    case CM_SSH:   wsprintfW(a, L"/k ssh %s", r->ips); ShellExecuteW(g_wnd, NULL, L"cmd.exe", a, NULL, SW_SHOW); break;
    }
}
static void open_target(int cmd) {
    int n=0;RES *rows=selected_snapshot(&n);if(!rows)return;
    if(confirm_multi_launch(n,L"Open connection"))for(int i=0;i<n;i++)if(rows[i].alive)
        open_target_one(&rows[i],cmd);
    xfree(rows);
}

static void set_type(int idx) {
    for (int i = -1; (i = (int)SendMessageW(g_list, LVM_GETNEXTITEM, i, LVNI_SELECTED)) >= 0;) {
        RES *r = row_res(i);
        if (!r->alive) continue;
        if (idx < 0) { ini_set(row_key(r), NULL); lstrcpyW(r->type, r->autotype); }
        else { ini_set(row_key(r), TYPES[idx]); lstrcpyW(r->type, TYPES[idx]); }
        for(int j=0;j<g_nmon;j++)if(g_mon[j].res.ip==r->ip)lstrcpynW(g_mon[j].res.type,r->type,24);
        pips_device_store(r);
        LVITEMW s = {0}; s.iSubItem = C_TYPE; s.pszText = r->type;
        SendMessageW(g_list, LVM_SETITEMTEXTW, i, (LPARAM)&s);
    }
}

static void comment_commit(int save) {
    if (g_cedit_row < 0 || !g_cedit) return;
    int row = g_cedit_row, multi=g_cedit_multi;g_cedit_row = -1;g_cedit_multi=0;
    HWND e = g_cedit; g_cedit = NULL;
    if (save && row < (int)SendMessageW(g_list, LVM_GETITEMCOUNT, 0, 0)) {
        WCHAR txt[128]; GetWindowTextW(e, txt, 128);
        for(int i=0;i<(int)SendMessageW(g_list,LVM_GETITEMCOUNT,0,0);i++){
            if(i!=row && (!multi || !(SendMessageW(g_list,LVM_GETITEMSTATE,i,LVIS_SELECTED)&LVIS_SELECTED)))continue;
            RES *r=row_res(i);if(!r->alive)continue;
            lstrcpynW(r->desc,txt,128);
            LVITEMW s={0};s.iSubItem=C_COMMENT;s.pszText=r->desc;
            SendMessageW(g_list,LVM_SETITEMTEXTW,i,(LPARAM)&s);
            ini_put(L"desc",row_key(r),txt[0]?txt:NULL);
            for(int j=0;j<g_nmon;j++)if(g_mon[j].res.ip==r->ip)lstrcpynW(g_mon[j].res.desc,txt,128);
            pips_device_store(r);
        }
        InvalidateRect(g_list, NULL, FALSE);
    }
    DestroyWindow(e);
    SetFocus(g_list);
}

static LRESULT CALLBACK ceditproc(HWND h, UINT m, WPARAM wp, LPARAM lp) {
    if (m == WM_KEYDOWN && wp == VK_RETURN) { comment_commit(1); return 0; }
    if (m == WM_KEYDOWN && wp == VK_ESCAPE) { comment_commit(0); return 0; }
    if (m == WM_KILLFOCUS) { comment_commit(1); return 0; }
    return CallWindowProcW(g_ceditproc, h, m, wp, lp);
}

static void comment_edit(int row) {
    if (row < 0 || !row_res(row)->alive) return;
    comment_commit(1);
    RECT rc = { LVIR_LABEL, C_COMMENT }; 
    if (!SendMessageW(g_list, LVM_GETSUBITEMRECT, row, (LPARAM)&rc)) return;
    RES *r = row_res(row);
    g_cedit_row = row;
    g_cedit_multi=(int)SendMessageW(g_list,LVM_GETSELECTEDCOUNT,0,0)>1;
    g_cedit = CreateWindowExW(0, L"EDIT", r->desc, WS_CHILD | WS_VISIBLE | WS_BORDER | ES_AUTOHSCROLL,
                              rc.left, rc.top, rc.right - rc.left, rc.bottom - rc.top,
                              g_list, (HMENU)ID_CEDIT, GetModuleHandleW(NULL), NULL);
    if (!g_cedit) { g_cedit_row = -1; return; }
    SendMessageW(g_cedit, WM_SETFONT, (WPARAM)g_font, TRUE);
    g_ceditproc = (WNDPROC)SetWindowLongPtrW(g_cedit, GWLP_WNDPROC, (LONG_PTR)ceditproc);
    SendMessageW(g_cedit, EM_SETSEL, 0, -1);
    SetFocus(g_cedit);
}

static void comment_clear_sel(void) {
    for (int i = -1; (i = (int)SendMessageW(g_list, LVM_GETNEXTITEM, i, LVNI_SELECTED)) >= 0;) {
        RES *r = row_res(i);
        r->desc[0] = 0;
        LVITEMW s = {0}; s.iSubItem = C_COMMENT; s.pszText = r->desc;
        SendMessageW(g_list, LVM_SETITEMTEXTW, i, (LPARAM)&s);
        ini_put(L"desc", row_key(r), NULL);
        for(int j=0;j<g_nmon;j++)if(g_mon[j].res.ip==r->ip)g_mon[j].res.desc[0]=0;
        pips_device_store(r);
    }
    InvalidateRect(g_list, NULL, FALSE);
}

static void context_menu(LPARAM lp) {
    POINT pt = { (short)LOWORD(lp), (short)HIWORD(lp) };
    int row = (int)SendMessageW(g_list, LVM_GETNEXTITEM, (WPARAM)-1, LVNI_FOCUSED | LVNI_SELECTED);
    if (row < 0) row = (int)SendMessageW(g_list, LVM_GETNEXTITEM, (WPARAM)-1, LVNI_SELECTED);
    g_ctxcol = C_IP;
    if (pt.x == -1 && pt.y == -1) {
        if(row<0)return;
        RECT ir = { LVIR_BOUNDS }; SendMessageW(g_list, LVM_GETITEMRECT, row, (LPARAM)&ir);
        pt.x = ir.left + S(20); pt.y = ir.bottom; ClientToScreen(g_list, &pt);
    } else {
        LVHITTESTINFO ht = {0}; ht.pt = pt; ScreenToClient(g_list, &ht.pt);
        if (SendMessageW(g_list, LVM_SUBITEMHITTEST, 0, (LPARAM)&ht) >= 0) {
            g_ctxcol = ht.iSubItem; row = ht.iItem;
            if(!(SendMessageW(g_list,LVM_GETITEMSTATE,row,LVIS_SELECTED)&LVIS_SELECTED)) {
                SendMessageW(g_list,LVM_SETITEMSTATE,(WPARAM)-1,(LPARAM)&(LVITEMW){.stateMask=LVIS_SELECTED,.state=0});
                LVITEMW it={0};it.stateMask=LVIS_SELECTED|LVIS_FOCUSED;it.state=LVIS_SELECTED|LVIS_FOCUSED;
                SendMessageW(g_list,LVM_SETITEMSTATE,row,(LPARAM)&it);
            }
        }
    }
    int selected=(int)SendMessageW(g_list,LVM_GETSELECTEDCOUNT,0,0);
    if(!selected||row<0)return;
    RES *r = row_res(row);
    HMENU m = CreatePopupMenu();
    WCHAR lab[160], val[40];
    const WCHAR *cell = col_text(r, g_ctxcol);
    lstrcpynW(val, cell, 33);
    if (lstrlenW(cell) > 32) lstrcatW(val, L"...");
    if (*val) wsprintfW(lab, L"Copy  \"%s\"", val); else wsprintfW(lab, L"Copy %s", COLNAME[g_ctxcol]);
    AppendMenuW(m, MF_STRING | (*val ? 0 : MF_GRAYED), CM_COPYCELL, lab);
    AppendMenuW(m, MF_STRING, CM_COPYIP, L"Copy IP");
    AppendMenuW(m, MF_STRING, CM_COPYMAC, L"Copy MAC address");
    AppendMenuW(m, MF_STRING, CM_COPYNAME, L"Copy name");
    AppendMenuW(m, MF_STRING, CM_COPYROW, L"Copy row\tCtrl+C");
    AppendMenuW(m, MF_SEPARATOR, 0, NULL);
    AppendMenuW(m, MF_STRING | (r->alive ? 0 : MF_GRAYED), CM_COMMENT,
                selected>1?L"Edit comment for selected...":L"Edit comment\tF2");
    AppendMenuW(m, MF_STRING | (r->desc[0] ? 0 : MF_GRAYED), CM_COMMENTCLR, L"Clear comment");
    AppendMenuW(m, MF_SEPARATOR, 0, NULL);
    HMENU sub = CreatePopupMenu();
    AppendMenuW(sub, MF_STRING | (lstrcmpW(r->type, r->autotype) ? 0 : MF_CHECKED), CM_TYPEAUTO, L"Automatic");
    AppendMenuW(sub, MF_SEPARATOR, 0, NULL);
    for (int i = 0; TYPES[i]; i++)
        AppendMenuW(sub, MF_STRING | (lstrcmpW(r->type, r->autotype) == 0 || lstrcmpW(r->type, TYPES[i]) ? 0 : MF_CHECKED),
                    CM_TYPE0 + i, TYPES[i]);
    AppendMenuW(m, MF_POPUP | (r->alive ? 0 : MF_GRAYED), (UINT_PTR)sub, L"Set type");
    AppendMenuW(m, MF_SEPARATOR, 0, NULL);
    UINT f = r->alive ? 0 : MF_GRAYED;
#define ACTSUB(PRT, defid, deftxt, title) do { \
        HMENU sm = CreatePopupMenu(); int any = 0; \
        AppendMenuW(sm, MF_STRING, defid, deftxt); \
        if((PRT)==P_FS)AppendMenuW(sm,MF_STRING,CM_SMB_OTHER,L"Login with different account..."); \
        for (int i = 0; i < g_nprof; i++) if (g_prof[i].proto == (PRT)) { \
            if (!any) { AppendMenuW(sm, MF_SEPARATOR, 0, NULL); any = 1; } \
            WCHAR t[130]; wsprintfW(t, L"%s  -  %s", g_prof[i].label, g_prof[i].user); \
            AppendMenuW(sm, MF_STRING | (lstrcmpW(r->auth, g_prof[i].label) ? 0 : MF_CHECKED), CM_PROFBASE + i, t); } \
        AppendMenuW(m, MF_POPUP | f, (UINT_PTR)sm, title); \
    } while (0)
    ACTSUB(P_CAM, CM_VIEW, L"Open (use saved login)", L"Open in viewer (IE/ActiveX)\tDouble-click");
    AppendMenuW(m, MF_STRING | f, CM_HTTP, L"Open in system browser");
    ACTSUB(P_FS, CM_SMB, L"Current Windows login", L"Explore shares");
    ACTSUB(P_RDP, CM_RDP, L"Default (ask)", L"Remote Desktop");
    ACTSUB(P_SSH, CM_SSH, L"Default", L"SSH");
    AppendMenuW(m, MF_STRING | (r->alive ? 0 : MF_GRAYED), CM_PING, L"Ping");
    HMENU monitoring = CreatePopupMenu();
    static const int intervals[] = {5,10,30,60};
    for(int k=0;k<4;k++) {
        WCHAR label[64];wsprintfW(label,L"Every %d seconds",intervals[k]);
        AppendMenuW(monitoring,MF_STRING,CM_MONBASE+k,label);
    }
    AppendMenuW(m,MF_POPUP,(UINT_PTR)monitoring,
                selected>1?L"Add / change Monitoring for selected":L"Add / change Monitoring");
    int monitored=0;
    for(int k=0;k<g_nmon;k++)if(!lstrcmpW(g_mon[k].res.ips,r->ips))monitored=1;
    if(monitored||selected>1)AppendMenuW(m,MF_STRING,CM_MONREMOVE,
                selected>1?L"Remove selected from Monitoring":L"Remove from Monitoring");
#undef ACTSUB
    if (r->alive) SetMenuDefaultItem(m, CM_VIEW, FALSE);
    else if (*val) SetMenuDefaultItem(m, CM_COPYCELL, FALSE);
    TrackPopupMenu(m, TPM_RIGHTBUTTON, pt.x, pt.y, 0, g_wnd, NULL);
    DestroyMenu(m);
}

/* ---------- ONVIF logins: DPAPI-encrypted (current Windows user), hex, in [onvif] of the ini ---------- */
static int ini_read(const WCHAR *sec, const WCHAR *key, WCHAR *out, int cap) {
    if (GetPrivateProfileStringW(sec, key, L"", out, cap, g_ini)) return 1;
    return GetPrivateProfileStringW(sec, key, L"", out, cap, g_ini2) > 0;
}
static void ini_put(const WCHAR *sec, const WCHAR *key, const WCHAR *val) {
    if (!val) {
        if (GetFileAttributesW(g_ini) != INVALID_FILE_ATTRIBUTES) WritePrivateProfileStringW(sec, key, NULL, g_ini);
        if (GetFileAttributesW(g_ini2) != INVALID_FILE_ATTRIBUTES) WritePrivateProfileStringW(sec, key, NULL, g_ini2);
        return;
    }
    if (!WritePrivateProfileStringW(sec, key, val, g_ini)) WritePrivateProfileStringW(sec, key, val, g_ini2);
}

/* ---------- credential profiles: {label, user, pass, protocol}, DPAPI-encrypted in the ini ---------- */
static void load_profiles(void) {
    g_nprof = 0;
    WCHAR *hex = (WCHAR *)xalloc(16384 * sizeof(WCHAR));
    if (!hex) return;
    if (ini_read(L"profiles", L"data", hex, 16384)) {
        int hl = lstrlenW(hex);
        BYTE *bin = (BYTE *)xalloc(hl / 2 + 1); DWORD n = 0;
        for (int k = 0; hex[k] && hex[k + 1]; k += 2) {
            int v = 0;
            for (int j = 0; j < 2; j++) { WCHAR c = hex[k + j]; v = v * 16 + (c >= 'a' ? c - 'a' + 10 : c >= 'A' ? c - 'A' + 10 : c - '0'); }
            bin[n++] = (BYTE)v;
        }
        DATA_BLOB in = { n, bin }, out = { 0, NULL };
        if (CryptUnprotectData(&in, NULL, NULL, NULL, NULL, CRYPTPROTECT_UI_FORBIDDEN, &out)) {
            const BYTE *p = out.pbData, *e = out.pbData + out.cbData;
            int cnt = (p < e) ? *p++ : 0;
            for (int i = 0; i < cnt && i < 100 && p < e; i++) {
                PROF *pr = &g_prof[g_nprof];
                memset(pr, 0, sizeof *pr);
                pr->proto = (p < e) ? *p++ : 0;
                if (pr->proto < 0 || pr->proto >= P_NPROTO) pr->proto = 0;
                WCHAR *flds[3]; flds[0] = pr->label; flds[1] = pr->user; flds[2] = pr->pass;
                int caps[3] = { 40, 64, 64 };
                for (int f = 0; f < 3; f++) {
                    /* each field stored as UTF-8 up to NUL */
                    const BYTE *st = p; while (p < e && *p) p++;
                    MultiByteToWideChar(CP_UTF8, 0, (const char *)st, (int)(p - st), flds[f], caps[f] - 1);
                    if (p < e) p++;
                }
                g_nprof++;
            }
            wipe(out.pbData, out.cbData);
            LocalFree(out.pbData);
        }
        xfree(bin);
    }
    xfree(hex);
}

static void save_profiles(void) {
    BYTE *raw = (BYTE *)xalloc(100 * 200 + 8); DWORD n = 0;
    if (!raw) return;
    raw[n++] = (BYTE)g_nprof;
    for (int i = 0; i < g_nprof; i++) {
        raw[n++] = (BYTE)g_prof[i].proto;
        WCHAR *flds[3]; flds[0] = g_prof[i].label; flds[1] = g_prof[i].user; flds[2] = g_prof[i].pass;
        for (int f = 0; f < 3; f++) {
            n += WideCharToMultiByte(CP_UTF8, 0, flds[f], -1, (char *)raw + n, 200, NULL, NULL);
            /* the -1 writes a trailing NUL already counted */
        }
    }
    DATA_BLOB in = { n, raw }, out = { 0, NULL };
    int ok = CryptProtectData(&in, L"ipscan", NULL, NULL, NULL, CRYPTPROTECT_UI_FORBIDDEN, &out);
    wipe(raw, n); xfree(raw);
    if (!ok) { ini_put(L"profiles", L"data", NULL); return; }
    WCHAR *hex = (WCHAR *)xalloc((out.cbData * 2 + 1) * sizeof(WCHAR));
    static const WCHAR hx[] = L"0123456789abcdef";
    for (DWORD k = 0; k < out.cbData; k++) { hex[k * 2] = hx[out.pbData[k] >> 4]; hex[k * 2 + 1] = hx[out.pbData[k] & 15]; }
    hex[out.cbData * 2] = 0;
    ini_put(L"profiles", L"data", hex);
    xfree(hex); LocalFree(out.pbData);
}

/* ---- Add / Edit one profile (modal sub-dialog) ---- */
static HWND g_ed, g_ed_l, g_ed_u, g_ed_p, g_ed_proto; static PROF g_ed_tmp; static int g_ed_ok;
static LRESULT CALLBACK proedit_proc(HWND w, UINT m, WPARAM wp, LPARAM lp) {
    switch (m) {
    case WM_CREATE: {
        HINSTANCE hi = ((LPCREATESTRUCTW)lp)->hInstance; HWND c;
#define CT(cls, txt, st, x, y, cx, cy, id) \
        c = CreateWindowExW((id>=10&&id<=13)?WS_EX_CLIENTEDGE:0, cls, txt, WS_CHILD|WS_VISIBLE|(st), S(x),S(y),S(cx),S(cy), w, (HMENU)(INT_PTR)(id), hi, NULL); \
        SendMessageW(c, WM_SETFONT, (WPARAM)g_font, TRUE);
        CT(L"STATIC", L"Label", 0, 14, 16, 70, 18, -1);
        CT(L"EDIT", g_ed_tmp.label, WS_TABSTOP|ES_AUTOHSCROLL, 90, 14, 200, 22, 10); g_ed_l = c;
        CT(L"STATIC", L"Username", 0, 14, 48, 70, 18, -1);
        CT(L"EDIT", g_ed_tmp.user, WS_TABSTOP|ES_AUTOHSCROLL, 90, 46, 200, 22, 11); g_ed_u = c;
        CT(L"STATIC", L"Password", 0, 14, 80, 70, 18, -1);
        CT(L"EDIT", g_ed_tmp.pass, WS_TABSTOP|ES_AUTOHSCROLL, 90, 78, 200, 22, 12); g_ed_p = c;  /* visible, not masked */
        CT(L"STATIC", L"Protocol", 0, 14, 112, 70, 18, -1);
        CT(L"COMBOBOX", L"", WS_TABSTOP|CBS_DROPDOWNLIST, 90, 110, 200, 200, 13); g_ed_proto = c;
        for (int i = 0; i < P_NPROTO; i++) SendMessageW(g_ed_proto, CB_ADDSTRING, 0, (LPARAM)PROTO_NAME[i]);
        SendMessageW(g_ed_proto, CB_SETCURSEL, g_ed_tmp.proto, 0);
        CT(L"BUTTON", L"OK", WS_TABSTOP|BS_DEFPUSHBUTTON, 130, 148, 76, 26, IDOK);
        CT(L"BUTTON", L"Cancel", WS_TABSTOP, 212, 148, 76, 26, IDCANCEL);
#undef CT
        SetFocus(g_ed_l);
        return 0;
    }
    case WM_COMMAND:
        if (LOWORD(wp) == IDOK) {
            GetWindowTextW(g_ed_l, g_ed_tmp.label, 40);
            GetWindowTextW(g_ed_u, g_ed_tmp.user, 64);
            GetWindowTextW(g_ed_p, g_ed_tmp.pass, 64);
            g_ed_tmp.proto = (int)SendMessageW(g_ed_proto, CB_GETCURSEL, 0, 0);
            if (g_ed_tmp.proto < 0) g_ed_tmp.proto = 0;
            if (!g_ed_tmp.label[0] && g_ed_tmp.user[0]) lstrcpyW(g_ed_tmp.label, g_ed_tmp.user);
            g_ed_ok = 1; DestroyWindow(w);
        } else if (LOWORD(wp) == IDCANCEL) DestroyWindow(w);
        return 0;
    case WM_CLOSE: DestroyWindow(w); return 0;
    case WM_DESTROY: g_ed = NULL; return 0;
    }
    return DefWindowProcW(w, m, wp, lp);
}
static int prof_edit(HWND owner, PROF *pr) {
    static int reg; HINSTANCE hi = GetModuleHandleW(NULL);
    if (!reg) {
        WNDCLASSEXW wc = {0}; wc.cbSize = sizeof wc; wc.lpfnWndProc = proedit_proc; wc.hInstance = hi;
        wc.hCursor = LoadCursor(NULL, IDC_ARROW); wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
        wc.lpszClassName = L"IpScanProfEdit"; RegisterClassExW(&wc); reg = 1;
    }
    g_ed_tmp = *pr; g_ed_ok = 0;
    RECT rc = { 0, 0, S(306), S(190) };
    DWORD st = WS_POPUP|WS_CAPTION|WS_SYSMENU, ex = WS_EX_DLGMODALFRAME;
    AdjustWindowRectEx(&rc, st, FALSE, ex);
    RECT pr2; GetWindowRect(owner, &pr2);
    int cx = rc.right - rc.left, cy = rc.bottom - rc.top;
    g_ed = CreateWindowExW(ex, L"IpScanProfEdit", L"Profile", st,
                           (pr2.left + pr2.right - cx) / 2, (pr2.top + pr2.bottom - cy) / 2, cx, cy, owner, NULL, hi, NULL);
    if (!g_ed) return 0;
    EnableWindow(owner, FALSE); ShowWindow(g_ed, SW_SHOW);
    MSG m;
    while (g_ed && GetMessageW(&m, NULL, 0, 0) > 0)
        if (!IsDialogMessageW(g_ed, &m)) { TranslateMessage(&m); DispatchMessageW(&m); }
    EnableWindow(owner, TRUE); SetActiveWindow(owner);
    if (g_ed_ok && g_ed_tmp.user[0]) { *pr = g_ed_tmp; return 1; }
    return 0;
}

/* ---- Profiles manager (list + Add / Edit / Delete) ---- */
static HWND g_dlg, g_plist;
static void prof_fill(void) {
    SendMessageW(g_plist, LVM_DELETEALLITEMS, 0, 0);
    for (int i = 0; i < g_nprof; i++) {
        LVITEMW it = {0}; it.mask = LVIF_TEXT; it.iItem = i; it.pszText = g_prof[i].label;
        SendMessageW(g_plist, LVM_INSERTITEMW, 0, (LPARAM)&it);
        LVITEMW s1 = {0}; s1.iSubItem = 1; s1.pszText = g_prof[i].user; SendMessageW(g_plist, LVM_SETITEMTEXTW, i, (LPARAM)&s1);
        LVITEMW s2 = {0}; s2.iSubItem = 2; s2.pszText = g_prof[i].pass; SendMessageW(g_plist, LVM_SETITEMTEXTW, i, (LPARAM)&s2);
        LVITEMW s3 = {0}; s3.iSubItem = 3; s3.pszText = (WCHAR *)PROTO_NAME[g_prof[i].proto]; SendMessageW(g_plist, LVM_SETITEMTEXTW, i, (LPARAM)&s3);
    }
}
static int prof_sel(void) { return (int)SendMessageW(g_plist, LVM_GETNEXTITEM, (WPARAM)-1, LVNI_SELECTED); }
static void prof_select(int i) {
    LVITEMW it = {0}; it.stateMask = LVIS_SELECTED | LVIS_FOCUSED; it.state = LVIS_SELECTED | LVIS_FOCUSED;
    SendMessageW(g_plist, LVM_SETITEMSTATE, i, (LPARAM)&it);
    SendMessageW(g_plist, LVM_ENSUREVISIBLE, i, FALSE);
    SetFocus(g_plist);
}

static LRESULT CALLBACK profmgr_proc(HWND w, UINT m, WPARAM wp, LPARAM lp) {
    switch (m) {
    case WM_CREATE: {
        HINSTANCE hi = ((LPCREATESTRUCTW)lp)->hInstance; HWND c;
        c = CreateWindowExW(0, L"STATIC",
            L"Credential profiles. Add any number (max 100). Passwords are shown here and stored encrypted for your "
            L"Windows account. When you connect, profiles matching that action's protocol are offered.",
            WS_CHILD|WS_VISIBLE, S(12), S(8), S(452), S(34), w, NULL, hi, NULL);
        SendMessageW(c, WM_SETFONT, (WPARAM)g_font, TRUE);
        g_plist = CreateWindowExW(WS_EX_CLIENTEDGE, WC_LISTVIEWW, L"", WS_CHILD|WS_VISIBLE|WS_TABSTOP|LVS_REPORT|LVS_SHOWSELALWAYS|LVS_SINGLESEL,
                                  S(12), S(46), S(452), S(210), w, (HMENU)500, hi, NULL);
        SendMessageW(g_plist, WM_SETFONT, (WPARAM)g_font, TRUE);
        SendMessageW(g_plist, LVM_SETEXTENDEDLISTVIEWSTYLE, 0, LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);
        SetWindowTheme(g_plist, L"Explorer", NULL);
        static const WCHAR *cn[4] = { L"Label", L"Username", L"Password", L"Protocol" };
        static const int cw[4] = { 120, 120, 120, 80 };
        for (int i = 0; i < 4; i++) { LVCOLUMNW col = {0}; col.mask = LVCF_TEXT|LVCF_WIDTH; col.pszText = (WCHAR *)cn[i]; col.cx = S(cw[i]); SendMessageW(g_plist, LVM_INSERTCOLUMNW, i, (LPARAM)&col); }
        prof_fill();
#define PB(txt, x, wd, id) c = CreateWindowExW(0, L"BUTTON", txt, WS_CHILD|WS_VISIBLE|WS_TABSTOP, S(x), S(264), S(wd), S(26), w, (HMENU)(INT_PTR)(id), hi, NULL); SendMessageW(c, WM_SETFONT, (WPARAM)g_font, TRUE);
        PB(L"Add", 12, 66, 501) PB(L"Edit", 84, 66, 502) PB(L"Delete", 156, 66, 503)
        PB(L"Up", 240, 50, 504) PB(L"Down", 294, 54, 505) PB(L"Close", 398, 66, IDOK)
#undef PB
        return 0;
    }
    case WM_COMMAND:
        switch (LOWORD(wp)) {
        case 501: if (g_nprof < 100) { PROF pr; memset(&pr, 0, sizeof pr); if (prof_edit(w, &pr)) { g_prof[g_nprof++] = pr; prof_fill(); } } break;
        case 502: { int i = prof_sel(); if (i >= 0 && prof_edit(w, &g_prof[i])) prof_fill(); break; }
        case 503: { int i = prof_sel(); if (i >= 0) { for (int k = i; k < g_nprof - 1; k++) g_prof[k] = g_prof[k + 1]; g_nprof--; prof_fill(); } break; }
        case 504: { int i = prof_sel(); if (i > 0) { PROF t = g_prof[i]; g_prof[i] = g_prof[i-1]; g_prof[i-1] = t; prof_fill(); prof_select(i-1); } break; }
        case 505: { int i = prof_sel(); if (i >= 0 && i < g_nprof - 1) { PROF t = g_prof[i]; g_prof[i] = g_prof[i+1]; g_prof[i+1] = t; prof_fill(); prof_select(i+1); } break; }
        case IDOK: DestroyWindow(w); break;
        }
        return 0;
    case WM_NOTIFY:
        if (((NMHDR *)lp)->idFrom == 500 && ((NMHDR *)lp)->code == NM_DBLCLK) {
            int i = prof_sel(); if (i >= 0 && prof_edit(w, &g_prof[i])) prof_fill();
        }
        return 0;
    case WM_CLOSE: DestroyWindow(w); return 0;
    case WM_DESTROY: save_profiles(); g_dlg = NULL; return 0;
    }
    return DefWindowProcW(w, m, wp, lp);
}

static void cred_dialog(void) {
    static int reg; HINSTANCE hi = GetModuleHandleW(NULL);
    if (!reg) {
        WNDCLASSEXW wc = {0}; wc.cbSize = sizeof wc; wc.lpfnWndProc = profmgr_proc; wc.hInstance = hi;
        wc.hCursor = LoadCursor(NULL, IDC_ARROW); wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
        wc.lpszClassName = L"IpScanProfiles"; RegisterClassExW(&wc); reg = 1;
    }
    RECT rc = { 0, 0, S(476), S(302) };
    DWORD st = WS_POPUP|WS_CAPTION|WS_SYSMENU, ex = WS_EX_DLGMODALFRAME;
    AdjustWindowRectEx(&rc, st, FALSE, ex);
    RECT pr; GetWindowRect(g_wnd, &pr);
    int cx = rc.right - rc.left, cy = rc.bottom - rc.top;
    g_dlg = CreateWindowExW(ex, L"IpScanProfiles", L"Credential profiles", st,
                            (pr.left + pr.right - cx) / 2, (pr.top + pr.bottom - cy) / 2, cx, cy, g_wnd, NULL, hi, NULL);
    if (!g_dlg) return;
    EnableWindow(g_wnd, FALSE); ShowWindow(g_dlg, SW_SHOW);
    MSG m;
    while (g_dlg && GetMessageW(&m, NULL, 0, 0) > 0)
        if (!IsDialogMessageW(g_dlg, &m)) { TranslateMessage(&m); DispatchMessageW(&m); }
    EnableWindow(g_wnd, TRUE); SetActiveWindow(g_wnd);
}

static void save_log(void) {
    WCHAR fn[MAX_PATH], msg[MAX_PATH + 120];
    lstrcpyW(fn, g_ini);
    int n = lstrlenW(fn);
    while (n && fn[n - 1] != '\\') n--;
    lstrcpyW(fn + n, L"ipscan-diagnostics.txt");
    HANDLE f = CreateFileW(fn, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
    if (f == INVALID_HANDLE_VALUE) {
        ExpandEnvironmentStringsW(L"%TEMP%\\ipscan-diagnostics.txt", fn, MAX_PATH);
        f = CreateFileW(fn, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
    }
    if (f == INVALID_HANDLE_VALUE) return;
    DWORD w;
    if (g_log) WriteFile(f, g_log, g_loglen, &w, NULL);
    CloseHandle(f);
    wsprintfW(msg, L"Diagnostics saved to:\n%s", fn);
    MessageBoxW(g_wnd, msg, L"PIPS Scanner", MB_ICONINFORMATION);
}

static void push_history(const WCHAR *val);
static void start_scan(void) {
    if (g_running) {
        InterlockedExchange(&g_stop, 1);
        SetWindowTextW(g_btn, L"Stopping"); EnableWindow(g_btn, FALSE);
        return;
    }
    int len = GetWindowTextLengthW(g_edit);
    if (!len) return;
    WCHAR *txt = (WCHAR *)xalloc((len + 1) * sizeof(WCHAR));
    GetWindowTextW(g_edit, txt, len + 1);
    push_history(txt);
    InterlockedIncrement(&g_osd_generation); /* invalidate previous scan's OSD replies */
    clear_results();
    g_debug = GetKeyState(VK_SHIFT) < 0;               /* Shift+Scan = also write a diagnostics file */
    g_loglen = 0; if (g_log) g_log[0] = 0;
    g_total = g_next = g_done = g_alive = g_stop = 0;
    g_running = 1; g_t0 = GetTickCount();
    g_msg[0] = 0;
    SetWindowTextW(g_btn, L"Stop");
    status_dirty();
    SetTimer(g_wnd, 1, 200, NULL);
    HANDLE h = CreateThread(NULL, 0, controller, txt, 0, NULL);
    if (h) CloseHandle(h);
}

/* ---------- range field: history (combo) + octet navigation (subclassed inner edit) ---------- */
static void load_history(void) {
    for (int i = 0; i < 5; i++) {
        WCHAR k[8], val[160]; wsprintfW(k, L"r%d", i);
        if (ini_read(L"history", k, val, 160) && val[0]) SendMessageW(g_edit, CB_ADDSTRING, 0, (LPARAM)val);
    }
}
static void push_history(const WCHAR *val) {
    if (!val || !val[0]) return;
    int idx = (int)SendMessageW(g_edit, CB_FINDSTRINGEXACT, (WPARAM)-1, (LPARAM)val);
    if (idx != CB_ERR) SendMessageW(g_edit, CB_DELETESTRING, idx, 0);
    SendMessageW(g_edit, CB_INSERTSTRING, 0, (LPARAM)val);
    while (SendMessageW(g_edit, CB_GETCOUNT, 0, 0) > 5) SendMessageW(g_edit, CB_DELETESTRING, 5, 0);
    int n = (int)SendMessageW(g_edit, CB_GETCOUNT, 0, 0);
    for (int i = 0; i < 5; i++) {
        WCHAR k[8], v[160]; wsprintfW(k, L"r%d", i); v[0] = 0;
        if (i < n) SendMessageW(g_edit, CB_GETLBTEXT, i, (LPARAM)v);
        ini_put(L"history", k, v[0] ? v : NULL);
    }
    SetWindowTextW(g_edit, val);                       /* keep the current range shown in the edit */
}
/* Tab / Shift+Tab hop between octets (runs between '.'); focus or a plain click selects a whole run.
   A run is a maximal span containing no '.' or ',' so ranges like "10.0.0.1-50, 192.168.1.0/24" work. */
static void inner_run(const WCHAR *t, int n, int pos, int *s, int *e) {
    if (pos > n) pos = n; if (pos < 0) pos = 0;
    int a = pos, b = pos;
    while (a > 0 && t[a - 1] != L'.' && t[a - 1] != L',') a--;
    while (b < n && t[b] != L'.' && t[b] != L',') b++;
    *s = a; *e = b;
}
static LRESULT CALLBACK inner_proc(HWND h, UINT msg, WPARAM wp, LPARAM lp) {
    if (msg == WM_GETDLGCODE) {
        LRESULT base = CallWindowProcW(g_innerproc, h, msg, wp, lp);
        WCHAR t[512]; int n = GetWindowTextW(h, t, 512);
        for (int i = 0; i < n; i++) if (t[i] == L'.') { base |= DLGC_WANTTAB; break; }
        return base;
    }
    if (msg == WM_KEYDOWN && wp == VK_TAB) {
        WCHAR t[512]; int n = GetWindowTextW(h, t, 512);
        DWORD a = 0, b = 0; SendMessageW(h, EM_GETSEL, (WPARAM)&a, (LPARAM)&b);
        int shift = GetKeyState(VK_SHIFT) < 0, ns = 0, ne = 0, moved = 0;
        if (!shift) { int e = (int)b; while (e < n && t[e] != L'.') e++;
                      if (e < n && t[e] == L'.') { ns = e + 1; ne = ns; while (ne < n && t[ne] != L'.') ne++; moved = 1; } }
        else       { int s = (int)a; while (s > 0 && t[s - 1] != L'.') s--;
                      if (s > 0 && t[s - 1] == L'.') { ne = s - 1; ns = ne; while (ns > 0 && t[ns - 1] != L'.') ns--; moved = 1; } }
        if (moved) { SendMessageW(h, EM_SETSEL, ns, ne); return 0; }
        { HWND p = GetParent(g_edit), nxt = GetNextDlgTabItem(p, g_edit, shift);  /* past last octet: next control */
          if (nxt) SetFocus(nxt); }
        return 0;
    }
    if (msg == WM_SETFOCUS) {
        LRESULT r = CallWindowProcW(g_innerproc, h, msg, wp, lp);
        SendMessageW(h, EM_SETSEL, 0, -1);             /* entering the field highlights everything */
        return r;
    }
    if (msg == WM_LBUTTONUP) {
        LRESULT r = CallWindowProcW(g_innerproc, h, msg, wp, lp);
        DWORD a = 0, b = 0; SendMessageW(h, EM_GETSEL, (WPARAM)&a, (LPARAM)&b);
        if (a == b) {                                  /* a plain click (no drag) selects the octet */
            WCHAR t[512]; int n = GetWindowTextW(h, t, 512), s, e;
            inner_run(t, n, (int)a, &s, &e);
            if (e > s) SendMessageW(h, EM_SETSEL, s, e);
        }
        return r;
    }
    return CallWindowProcW(g_innerproc, h, msg, wp, lp);
}

static void default_range(void) {
    load_interfaces();
    MIB_IPFORWARDROW rt; DWORD gw = 0;
    if (GetBestRoute(inet_addr("8.8.8.8"), 0, &rt) == NO_ERROR) gw = ntohl(rt.dwForwardNextHop);
    for (int i = 0; i < g_nif; i++) {
        DWORD ip = g_if[i].ip, mk = g_if[i].mask;
        if (gw && (gw & mk) != (ip & mk)) continue;
        WCHAR a[16], b[64]; DWORD net = ip & mk;
        if (mk == 0xFFFFFF00) { ip2w(net + 1, a); wsprintfW(b, L"%s-254", a); }
        else { int bits = 0; for (DWORD m = mk; m; m <<= 1) bits++; ip2w(net, a); wsprintfW(b, L"%s/%d", a, bits); }
        SetWindowTextW(g_edit, b);
        return;
    }
    SetWindowTextW(g_edit, L"192.168.1.1-254");
}

static void layout(void) {
    RECT rc; GetClientRect(g_wnd, &rc);
    int ph = PANEL_H(), sh = STATUS_H(), h = S(26), y = ROW1_Y();
    int bw = S(84), cw = S(96), gap = S(6), m = S(10), el = S(58);
    int x = rc.right - m - cw;
    MoveWindow(g_chk, x, y, cw, h, TRUE);   x -= gap + bw;
    MoveWindow(g_login, x, y, bw, h, TRUE); x -= gap + bw;
    MoveWindow(g_exp, x, y, bw, h, TRUE);   x -= gap + bw;
    MoveWindow(g_btn, x, y, bw, h, TRUE);   x -= gap + S(4);
    MoveWindow(g_edit, el, y + 1, x - el > S(80) ? x - el : S(80), S(160), TRUE);  /* tall: 4th arg is dropdown height */
    MoveWindow(g_search, el, ROW2_Y() + 1, rc.right - el - m, h - 2, TRUE);
    MoveWindow(g_upd, rc.right-S(96), rc.bottom-sh+S(3), S(86), S(20), TRUE);
    MoveWindow(g_list, TABW(), ph, rc.right - TABW(), rc.bottom - ph - sh, TRUE);
    InvalidateRect(g_wnd, NULL, FALSE);
}

static HWND mkbutton(const WCHAR *t, int id, HWND parent, HINSTANCE hi) {
    HWND b = CreateWindowExW(0, L"BUTTON", t, WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_OWNERDRAW,
                             0, 0, 0, 0, parent, (HMENU)(INT_PTR)id, hi, NULL);
    g_btnproc = (WNDPROC)SetWindowLongPtrW(b, GWLP_WNDPROC, (LONG_PTR)btnproc);
    return b;
}

static LRESULT CALLBACK wndproc(HWND w, UINT msg, WPARAM wp, LPARAM lp) {
    switch (msg) {
    case WM_CREATE: {
        g_wnd = w;
        HMENU menu=CreateMenu(),file=CreatePopupMenu();
        AppendMenuW(file,MF_STRING,CM_BACKUP,L"Export Backup...");
        AppendMenuW(file,MF_STRING,CM_RESTORE,L"Import Backup...");
        AppendMenuW(file,MF_SEPARATOR,0,NULL);
        AppendMenuW(file,MF_STRING,CM_DATAFOLDER,L"Open Data Folder");
        AppendMenuW(menu,MF_POPUP,(UINT_PTR)file,L"File");
        SetMenu(w,menu);
        NONCLIENTMETRICSW nm; nm.cbSize = sizeof nm;
        SystemParametersInfoW(SPI_GETNONCLIENTMETRICS, sizeof nm, &nm, 0);
        g_font = CreateFontIndirectW(&nm.lfMessageFont);
        nm.lfMessageFont.lfWeight = FW_BOLD;
        g_bold = CreateFontIndirectW(&nm.lfMessageFont);
        HINSTANCE hi = ((LPCREATESTRUCTW)lp)->hInstance;

        g_edit = CreateWindowExW(0, L"COMBOBOX", L"",
                                 WS_CHILD | WS_VISIBLE | WS_TABSTOP | WS_VSCROLL | CBS_DROPDOWN | CBS_AUTOHSCROLL,
                                 0, 0, 0, 0, w, (HMENU)ID_EDIT, hi, NULL);
        { COMBOBOXINFO cbi = { sizeof cbi }; GetComboBoxInfo(g_edit, &cbi); g_editinner = cbi.hwndItem;
          if (g_editinner) g_innerproc = (WNDPROC)SetWindowLongPtrW(g_editinner, GWLP_WNDPROC, (LONG_PTR)inner_proc); }
        g_btn = mkbutton(L"Scan", ID_SCAN, w, hi);
        g_exp = mkbutton(L"Export...", ID_EXPORT, w, hi);
        g_login = mkbutton(L"Login...", ID_LOGIN, w, hi);
        g_upd = mkbutton(L"Update MAC", ID_UPDATE, w, hi);
        g_chk = mkbutton(L"Alive only", ID_ALIVE, w, hi);
        g_search = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"", WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_AUTOHSCROLL,
                                   0, 0, 0, 0, w, (HMENU)ID_SEARCH, hi, NULL);
        SendMessageW(g_search, WM_SETFONT, (WPARAM)g_font, TRUE);
        SendMessageW(g_search, EM_SETMARGINS, EC_LEFTMARGIN | EC_RIGHTMARGIN, MAKELONG(S(4), S(4)));
        SendMessageW(g_search, EM_SETCUEBANNER, TRUE, (LPARAM)L"type to filter rows (IP, name, MAC, maker, type, comment, details)");
        g_list = CreateWindowExW(0, WC_LISTVIEWW, L"", WS_CHILD | WS_VISIBLE | WS_TABSTOP | LVS_REPORT | LVS_SHOWSELALWAYS,
                                 0, 0, 0, 0, w, (HMENU)ID_LIST, hi, NULL);
        SendMessageW(g_edit, WM_SETFONT, (WPARAM)g_font, TRUE);
        SendMessageW(g_list, WM_SETFONT, (WPARAM)g_font, TRUE);
        if (g_editinner) {
            SendMessageW(g_editinner, EM_SETMARGINS, EC_LEFTMARGIN | EC_RIGHTMARGIN, MAKELONG(S(4), S(4)));
            SendMessageW(g_editinner, EM_SETCUEBANNER, TRUE, (LPARAM)L"192.168.1.1-254, 10.0.0.0/24, 172.16.5.10, nvr01  (Tab hops between octets)");
        }
        SetWindowTheme(g_list, L"Explorer", NULL);
        SendMessageW(g_list, LVM_SETEXTENDEDLISTVIEWSTYLE, 0,
                     LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER | LVS_EX_HEADERDRAGDROP | LVS_EX_LABELTIP);
        SendMessageW(g_list, LVM_SETIMAGELIST, LVSIL_SMALL, (LPARAM)make_dots());
        for (int i = 0; i < NCOLS; i++) {
            LVCOLUMNW c = {0};
            c.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_FMT; c.pszText = (WCHAR *)COLNAME[i]; c.cx = S(COLW[i]);
            c.fmt = i == C_PING ? LVCFMT_RIGHT : LVCFMT_LEFT;
            SendMessageW(g_list, LVM_INSERTCOLUMNW, i, (LPARAM)&c);
        }
        default_range();
        load_history();
        if (SendMessageW(g_edit, CB_GETCOUNT, 0, 0) > 0) {   /* prefer the last range the user scanned */
            WCHAR v[160]; SendMessageW(g_edit, CB_GETLBTEXT, 0, (LPARAM)v); SetWindowTextW(g_edit, v);
        }
        { WCHAR v[8]; if (ini_read(L"ui", L"aliveonly", v, 8)) g_alive_only = (v[0] == L'1'); }
        SetTimer(w, 2, 500, NULL);
        return 0;
    }
    case WM_SIZE: layout(); RedrawWindow(w, NULL, NULL, RDW_INVALIDATE | RDW_ALLCHILDREN); return 0;
    case WM_LBUTTONDOWN: {
        int i = tab_hit((short)LOWORD(lp), (short)HIWORD(lp));
        if(i==-2){g_scanner_expanded=!g_scanner_expanded;pips_ui_state_save();}
        else if(i==-3){g_monitor_expanded=!g_monitor_expanded;pips_ui_state_save();g_mon_mode=1;g_mon_subnet=-1;refill();}
        else if(i>=100){g_mon_mode=1;g_mon_subnet=i-100;refill();}
        else if(i>=0){g_mon_mode=0;g_cat=i;refill();}
        invalidate_tabs();
        return 0;
    }
    case WM_MOUSEMOVE: {
        int i = tab_hit((short)LOWORD(lp), (short)HIWORD(lp));
        if (i != g_tabhot) {
            g_tabhot = i; invalidate_tabs();
            TRACKMOUSEEVENT te = { sizeof te, TME_LEAVE, w, 0 }; TrackMouseEvent(&te);
        }
        return 0;
    }
    case WM_MOUSELEAVE: if (g_tabhot != -1) { g_tabhot = -1; invalidate_tabs(); } return 0;
    case WM_GETMINMAXINFO: ((MINMAXINFO *)lp)->ptMinTrackSize.x = S(560); ((MINMAXINFO *)lp)->ptMinTrackSize.y = S(260); return 0;
    case WM_SETFOCUS: SetFocus(g_editinner ? g_editinner : g_edit); return 0;
    case WM_ERASEBKGND: return 1;
    case WM_PAINT: {
        PAINTSTRUCT ps; HDC dc = BeginPaint(w, &ps);
        RECT rc; GetClientRect(w, &rc);
        HDC md = CreateCompatibleDC(dc);
        HBITMAP bm = CreateCompatibleBitmap(dc, rc.right, rc.bottom), ob = SelectObject(md, bm);
        int sh = STATUS_H(), top = rc.bottom - sh;
        paint_panel(md, rc.right);
        paint_tabs(md, PANEL_H(), top);
        paint_status(md, rc.right, top);
        BitBlt(dc, 0, 0, rc.right, PANEL_H(), md, 0, 0, SRCCOPY);
        BitBlt(dc, 0, PANEL_H(), TABW(), top - PANEL_H(), md, 0, PANEL_H(), SRCCOPY);
        BitBlt(dc, 0, top, rc.right, sh, md, 0, top, SRCCOPY);
        SelectObject(md, ob); DeleteObject(bm); DeleteDC(md);
        EndPaint(w, &ps);
        return 0;
    }
    case WM_DRAWITEM: draw_item((DRAWITEMSTRUCT *)lp); return TRUE;
    case WM_COMMAND:
        switch (LOWORD(wp)) {
        case ID_SCAN: case IDOK: start_scan(); break;
        case ID_EXPORT: export_csv(); break;
        case CM_BACKUP: pips_backup_export(); break;
        case CM_RESTORE: pips_backup_import(); break;
        case CM_DATAFOLDER: pips_open_data_folder(); break;
        case ID_LOGIN: cred_dialog(); break;
        case ID_UPDATE:
            if (!g_updating && !g_running) {
                g_updating = 1; EnableWindow(g_upd, FALSE); SetWindowTextW(g_upd, L"Updating");
                status_dirty();
                HANDLE th = CreateThread(NULL, 0, update_thread, NULL, 0, NULL);
                if (th) CloseHandle(th); else { g_updating = 0; EnableWindow(g_upd, TRUE); SetWindowTextW(g_upd, L"Update MAC"); }
            }
            break;
        case CM_COMMENT: comment_edit((int)SendMessageW(g_list, LVM_GETNEXTITEM, (WPARAM)-1, LVNI_FOCUSED | LVNI_SELECTED)); break;
        case CM_COMMENTCLR: comment_clear_sel(); break;
        case ID_ALIVE:
            g_alive_only = !g_alive_only;
            ini_put(L"ui", L"aliveonly", g_alive_only ? L"1" : L"0");
            InvalidateRect(g_chk, NULL, FALSE);
            refill();
            break;
        case ID_SEARCH:
            if (HIWORD(wp) == EN_CHANGE) { GetWindowTextW(g_search, g_filter, 128); refill(); }
            break;
        case CM_COPYCELL: copy_sel(g_ctxcol); break;
        case CM_COPYIP: copy_sel(C_IP); break;
        case CM_COPYMAC: copy_sel(C_MAC); break;
        case CM_COPYNAME: copy_sel(C_NAME); break;
        case CM_COPYROW: copy_sel(-1); break;
        case CM_TYPEAUTO: set_type(-1); break;
        case CM_VIEW: open_viewer_selected(); break;
        case CM_PING: ping_sel(); break;
        case CM_SMB_OTHER: open_target(CM_SMB_OTHER); break;
        case CM_MONREMOVE: monitoring_selected(0,1); break;
        case CM_MONBASE: case CM_MONBASE+1: case CM_MONBASE+2: case CM_MONBASE+3: {
            static const int iv[]={5,10,30,60};
            monitoring_selected(iv[LOWORD(wp)-CM_MONBASE],0); break;
        }
        default:
            if (LOWORD(wp) >= CM_HTTP && LOWORD(wp) <= CM_SSH) open_target(LOWORD(wp));
            else if (LOWORD(wp) >= CM_TYPE0 && LOWORD(wp) < CM_TYPE0 + 15) set_type(LOWORD(wp) - CM_TYPE0);
            else if (LOWORD(wp) >= CM_PROFBASE && LOWORD(wp) < CM_PROFBASE + 100) {
                int idx = LOWORD(wp) - CM_PROFBASE;
                int n=0;RES *rows=selected_snapshot(&n);
                if(rows&&idx<g_nprof&&confirm_multi_launch(n,L"Connect with credential profile"))
                    for(int i=0;i<n;i++)if(rows[i].alive)apply_profile(&rows[i],&g_prof[idx]);
                xfree(rows);
            }
        }
        return 0;
    case WM_NOTIFY: {
        NMHDR *h = (NMHDR *)lp;
        if (h->hwndFrom != g_list) break;
        if (h->code == NM_CUSTOMDRAW) {
            NMLVCUSTOMDRAW *cd = (NMLVCUSTOMDRAW *)lp;
            if (cd->nmcd.dwDrawStage == CDDS_PREPAINT) return CDRF_NOTIFYITEMDRAW;
            if (cd->nmcd.dwDrawStage == CDDS_ITEMPREPAINT) {
                RES *r = (RES *)cd->nmcd.lItemlParam;
                if (r && !r->alive) { cd->clrTextBk = CLR_DEADBG; cd->clrText = CLR_DEADTX; }
                else { cd->clrTextBk = (cd->nmcd.dwItemSpec & 1) ? CLR_ALTBG : RGB(255, 255, 255); cd->clrText = RGB(25, 35, 55); }
                return CDRF_NOTIFYSUBITEMDRAW;
            }
            if (cd->nmcd.dwDrawStage == (CDDS_ITEMPREPAINT | CDDS_SUBITEM)) {
                RES *r = (RES *)cd->nmcd.lItemlParam;
                if (cd->iSubItem == C_COMMENT) {
                    if (r && !r->alive) cd->clrTextBk = RGB(255, 236, 224);
                    else cd->clrTextBk = (cd->nmcd.dwItemSpec & 1) ? RGB(255, 246, 232) : RGB(255, 250, 240);
                    if (r && r->desc[0]) cd->clrText = RGB(120, 72, 20);
                }
                return CDRF_NEWFONT;
            }
            return CDRF_DODEFAULT;
        }
        if (h->code == LVN_COLUMNCLICK) {
            int c = ((NMLISTVIEW *)lp)->iSubItem;
            g_sortdir = (c == g_sortcol) ? -g_sortdir : 1; g_sortcol = c;
            SendMessageW(g_list, LVM_SORTITEMS, 0, (LPARAM)cmp);
            InvalidateRect(g_list, NULL, FALSE);
        } else if (h->code == NM_DBLCLK) {
            NMITEMACTIVATE *a = (NMITEMACTIVATE *)lp;
            if (a->iItem >= 0 && a->iSubItem == C_COMMENT) comment_edit(a->iItem);
            else if (a->iItem >= 0 && row_res(a->iItem)->alive) {
                RES *rr = row_res(a->iItem);
                const PROF *pr = prof_by_label(rr->auth);
                if (pr) apply_profile(rr, pr);               /* remembered profile -> automatic */
                else if (g_cat == 4) open_target(CM_RDP);
                else if (cat_of(rr) == 3) open_target(CM_SMB);
                else open_viewer_sel();
            }
        } else if (h->code == LVN_KEYDOWN) {
            WORD k = ((NMLVKEYDOWN *)lp)->wVKey;
            if (k == VK_F2) comment_edit((int)SendMessageW(g_list, LVM_GETNEXTITEM, (WPARAM)-1, LVNI_FOCUSED | LVNI_SELECTED));
            if (GetKeyState(VK_CONTROL) < 0 && k == 'C') copy_sel(-1);
            if (GetKeyState(VK_CONTROL) < 0 && k == 'A') {
                LVITEMW it = {0}; it.stateMask = it.state = LVIS_SELECTED;
                SendMessageW(g_list, LVM_SETITEMSTATE, (WPARAM)-1, (LPARAM)&it);
            }
        }
        break;
    }
    case WM_CONTEXTMENU:
        if ((HWND)wp == g_list) { context_menu(lp); return 0; }
        break;
    case WM_SHARE: share_result((SHRES *)lp); return 0;
    case WM_PINGMSG: set_msg((WCHAR *)lp); xfree((void *)lp); return 0;
    case WM_PINGDOT: {
        PipsPingDot *d=(PipsPingDot*)lp;
        if(d && d->generation==(DWORD)g_ping_generation && d->seq>=0 && d->seq<4) {
            g_ping_ok[d->seq]=d->ok;g_ping_ms[d->seq]=d->rtt;
            if(d->seq+1>g_ping_count)g_ping_count=d->seq+1;
            if(g_ping_count==4){g_ping_active=0;g_ping_until=GetTickCount()+15000;}
            status_dirty();
        }
        xfree(d);return 0;
    }
    case WM_UPDDONE: {
        g_updating = 0; EnableWindow(g_upd, TRUE); SetWindowTextW(g_upd, L"Update MAC"); status_dirty();
        WCHAR m[160];
        if (wp) wsprintfW(m, L"MAC database updated:  %lu entries loaded.\nSaved next to the program.", (DWORD)wp);
        else lstrcpyW(m, L"Could not download the MAC database.\nCheck the internet connection and try again.");
        MessageBoxW(w, m, L"Update MAC DB", wp ? MB_ICONINFORMATION : MB_ICONWARNING);
        return 0;
    }
    case WM_TIMER:
        if (wp == 2) {
            if (g_msg[0] && (int)(g_msg_until - GetTickCount()) <= 0) g_msg[0] = 0;
            pips_monitor_tick();
            static DWORD last_prune;
            if(GetTickCount()-last_prune>3600000){pips_monitor_prune();last_prune=GetTickCount();}
            status_dirty();
        }
        else status_dirty();
        return 0;
    case WM_RESULT: add_result((RES *)lp); return 0;
    case WM_MONPING: pips_monitor_result((PipsMonResult*)lp); return 0;
    case WM_OSDNAME: pips_osd_finish((PipsOsdJob*)lp); return 0;
    case WM_ERRMSG:
        MessageBoxW(w, (WCHAR *)lp, L"PIPS Scanner", MB_ICONWARNING);
        xfree((void *)lp); return 0;
    case WM_DONE:
        g_running = 0; g_elapsed = GetTickCount() - g_t0; KillTimer(w, 1);
        if (g_nres) { SendMessageW(g_list, LVM_SORTITEMS, 0, (LPARAM)cmp); InvalidateRect(g_list, NULL, FALSE); }
        recount_tabs(); invalidate_tabs();
        status_dirty();
        SetWindowTextW(g_btn, L"Scan"); EnableWindow(g_btn, TRUE);
        if (g_debug) save_log();
        pips_osd_start_scan_retry();
        return 0;
    case WM_CLOSE:
        InterlockedExchange(&g_stop, 1);
        DestroyWindow(w); return 0;
    case WM_DESTROY: pips_data_shutdown(); PostQuitMessage(0); return 0;
    }
    return DefWindowProcW(w, msg, wp, lp);
}

int WINAPI wWinMain(HINSTANCE hi, HINSTANCE prev, LPWSTR cmdline, int show) {
    (void)prev; (void)cmdline;
    WSADATA wd; WSAStartup(MAKEWORD(2, 2), &wd);
    INITCOMMONCONTROLSEX ic = { sizeof ic, ICC_LISTVIEW_CLASSES | ICC_STANDARD_CLASSES };
    InitCommonControlsEx(&ic);
    InitializeCriticalSection(&g_cs);
    ini_init();
    load_profiles();
    load_oui();
    OleInitialize(NULL);
    ie_feature_setup();

    {   /* ipscan.exe --view 192.168.1.10  -> just the viewer window */
        const WCHAR *cl = GetCommandLineW(), *v = cl;
        for (; *v; v++) if (v[0] == '-' && v[1] == '-' && v[2] == 'v' && v[3] == 'i' && v[4] == 'e' && v[5] == 'w') break;
        if (*v) {
            v += 6; while (*v == ' ') v++;
            WCHAR target[128], vu[80] = L"", vp[80] = L""; int n = 0;
            while (v[n] && v[n] != ' ' && v[n] != '"' && n < 127) { target[n] = v[n]; n++; }
            target[n] = 0;
            GetEnvironmentVariableW(L"IPSCAN_VU", vu, 80);
            GetEnvironmentVariableW(L"IPSCAN_VP", vp, 80);
            SetEnvironmentVariableW(L"IPSCAN_VU", NULL); SetEnvironmentVariableW(L"IPSCAN_VP", NULL);
            if (n) {
                NONCLIENTMETRICSW nm; nm.cbSize = sizeof nm;
                SystemParametersInfoW(SPI_GETNONCLIENTMETRICS, sizeof nm, &nm, 0);
                g_font = CreateFontIndirectW(&nm.lfMessageFont);
                HDC dc0 = GetDC(NULL); g_dpi = GetDeviceCaps(dc0, LOGPIXELSY); ReleaseDC(NULL, dc0);
                g_view_standalone = 1;
                open_viewer(NULL, hi, target, vu, vp);
                MSG m;
                while (GetMessageW(&m, NULL, 0, 0) > 0) {
                    if (viewer_pretranslate(&m)) continue;
                    TranslateMessage(&m); DispatchMessageW(&m);
                }
                ExitProcess(0);
            }
        }
    }

    pips_data_init(); pips_monitor_load();pips_ui_state_load();
    WNDCLASSEXW wc = {0};
    wc.cbSize = sizeof wc; wc.lpfnWndProc = wndproc; wc.hInstance = hi;
    wc.style = CS_HREDRAW | CS_VREDRAW;
    wc.hCursor = LoadCursor(NULL, IDC_ARROW); wc.hbrBackground = NULL;
    wc.hIcon = LoadIconW(hi, MAKEINTRESOURCEW(1)); if (!wc.hIcon) wc.hIcon = LoadIcon(NULL, IDI_APPLICATION);
    wc.lpszClassName = L"MiniIpScan";
    RegisterClassExW(&wc);

    HDC dc = GetDC(NULL); g_dpi = GetDeviceCaps(dc, LOGPIXELSY); ReleaseDC(NULL, dc);
    HWND w = CreateWindowExW(0, wc.lpszClassName, L"PIPS Scanner", WS_OVERLAPPEDWINDOW | WS_CLIPCHILDREN,
                             CW_USEDEFAULT, CW_USEDEFAULT, S(1080), S(600), NULL, NULL, hi, NULL);
    ShowWindow(w, show);

    MSG m;
    while (GetMessageW(&m, NULL, 0, 0) > 0) {
        if (m.message == WM_KEYDOWN && m.wParam == VK_RETURN && (m.hwnd == g_edit || m.hwnd == g_editinner)) { start_scan(); continue; }
        if (m.message == WM_KEYDOWN && m.wParam == VK_RETURN && m.hwnd == g_list) { open_viewer_sel(); continue; }
        if (viewer_pretranslate(&m)) continue;
        if (GetAncestor(m.hwnd, GA_ROOT) != w) { TranslateMessage(&m); DispatchMessageW(&m); continue; }
        if (m.message == WM_KEYDOWN && m.wParam == VK_F5) { if (!g_running) start_scan(); continue; }
        if (IsDialogMessageW(w, &m)) continue;
        TranslateMessage(&m); DispatchMessageW(&m);
    }
    ExitProcess(0);
}


static int VS(int v) { return S(v); }
static HFONT view_font(void) { return g_font; }
#include "webview.c"
