/* Portable snapshot: SQLite and legacy INI settings plus password-encrypted
   credential profiles. Database/history is NOT encrypted; credentials are. */
#pragma pack(push,1)
typedef struct {
    char magic[8]; DWORD version; unsigned long long db_bytes;
    DWORD ini_bytes, profile_bytes;
    BYTE salt[16], nonce[12], tag[16];
} PipsBackupHeader;
#pragma pack(pop)
static void save_profiles(void);

static int pips_backup_password(WCHAR *password, int importing) {
    CREDUI_INFOW ui={0};ui.cbSize=sizeof ui;ui.hwndParent=g_wnd;
    ui.pszCaptionText=importing?L"Import PIPS Backup":L"Export PIPS Backup";
    ui.pszMessageText=importing?
        L"Enter the password used to encrypt the login profiles in this backup.":
        L"Enter a strong backup password (8+ characters). Login profiles will be encrypted for migration.\n"
        L"Device/monitoring history is included but is NOT encrypted.";
    WCHAR username[80]=L"PIPS Backup";BOOL save=FALSE;
    DWORD rc=CredUIPromptForCredentialsW(&ui,L"PIPS Scanner Backup",NULL,0,
        username,80,password,128,&save,CREDUI_FLAGS_GENERIC_CREDENTIALS|
        CREDUI_FLAGS_DO_NOT_PERSIST|CREDUI_FLAGS_ALWAYS_SHOW_UI);
    wipe(username,sizeof username);
    if(rc!=NO_ERROR)return 0;
    if(lstrlenW(password)<8) {
        MessageBoxW(g_wnd,L"Backup passwords must contain at least 8 characters.",L"PIPS Backup",MB_ICONWARNING);
        wipe(password,128*sizeof(WCHAR));return 0;
    }
    return 1;
}
static int pips_backup_crypto(int encrypt, const WCHAR *password, PipsBackupHeader *h,
                              const BYTE *src, BYTE *dst, DWORD length) {
    BCRYPT_ALG_HANDLE sha=NULL,aes=NULL;BCRYPT_KEY_HANDLE key=NULL;
    BYTE keybytes[32];memset(keybytes,0,sizeof keybytes);
    int ok=0;
    if(encrypt && (BCryptGenRandom(NULL,h->salt,sizeof h->salt,BCRYPT_USE_SYSTEM_PREFERRED_RNG)<0 ||
                   BCryptGenRandom(NULL,h->nonce,sizeof h->nonce,BCRYPT_USE_SYSTEM_PREFERRED_RNG)<0))goto finish;
    if(BCryptOpenAlgorithmProvider(&sha,BCRYPT_SHA256_ALGORITHM,NULL,BCRYPT_ALG_HANDLE_HMAC_FLAG)<0)goto finish;
    if(BCryptDeriveKeyPBKDF2(sha,(PUCHAR)password,lstrlenW(password)*sizeof(WCHAR),
        h->salt,sizeof h->salt,250000,keybytes,sizeof keybytes,0)<0)goto finish;
    if(BCryptOpenAlgorithmProvider(&aes,BCRYPT_AES_ALGORITHM,NULL,0)<0)goto finish;
    if(BCryptSetProperty(aes,BCRYPT_CHAINING_MODE,(PUCHAR)BCRYPT_CHAIN_MODE_GCM,
        sizeof BCRYPT_CHAIN_MODE_GCM,0)<0)goto finish;
    if(BCryptGenerateSymmetricKey(aes,&key,NULL,0,keybytes,sizeof keybytes,0)<0)goto finish;
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO auth;
    BCRYPT_INIT_AUTH_MODE_INFO(auth);
    auth.pbNonce=h->nonce;auth.cbNonce=sizeof h->nonce;
    auth.pbTag=h->tag;auth.cbTag=sizeof h->tag;
    ULONG written=0;
    NTSTATUS status=encrypt?
        BCryptEncrypt(key,(PUCHAR)src,length,&auth,NULL,0,dst,length,&written,0):
        BCryptDecrypt(key,(PUCHAR)src,length,&auth,NULL,0,dst,length,&written,0);
    ok=(status>=0 && written==length);
finish:
    wipe(keybytes,sizeof keybytes);
    if(key)BCryptDestroyKey(key);
    if(aes)BCryptCloseAlgorithmProvider(aes,0);
    if(sha)BCryptCloseAlgorithmProvider(sha,0);
    return ok;
}
static int pips_file_dialog(int saving, WCHAR *path) {
    path[0]=0;
    OPENFILENAMEW of={0};of.lStructSize=sizeof of;of.hwndOwner=g_wnd;
    of.lpstrFilter=L"PIPS backup (*.pipsbackup)\0*.pipsbackup\0All files\0*.*\0\0";
    of.lpstrFile=path;of.nMaxFile=MAX_PATH;
    of.lpstrDefExt=L"pipsbackup";
    of.Flags=OFN_PATHMUSTEXIST | (saving?OFN_OVERWRITEPROMPT:OFN_FILEMUSTEXIST);
    return saving?GetSaveFileNameW(&of):GetOpenFileNameW(&of);
}
static int pips_temp_db(WCHAR *path) {
    WCHAR dir[MAX_PATH];DWORD n=GetTempPathW(MAX_PATH,dir);
    if(!n||n>=MAX_PATH)return 0;
    return GetTempFileNameW(dir,L"PIP",0,path)!=0;
}
static int pips_copy_bytes(HANDLE from, HANDLE to, unsigned long long len) {
    BYTE buffer[65536];
    while(len) {
        DWORD chunk=len>sizeof buffer?sizeof buffer:(DWORD)len, n=0,w=0;
        if(!ReadFile(from,buffer,chunk,&n,NULL)||n!=chunk)return 0;
        if(!WriteFile(to,buffer,chunk,&w,NULL)||w!=chunk)return 0;
        len-=chunk;
    }
    return 1;
}
static DWORD pips_ini_readall(BYTE **out) {
    *out=NULL;
    const WCHAR *path=GetFileAttributesW(g_ini)!=INVALID_FILE_ATTRIBUTES?g_ini:g_ini2;
    HANDLE f=CreateFileW(path,GENERIC_READ,FILE_SHARE_READ|FILE_SHARE_WRITE,NULL,OPEN_EXISTING,0,NULL);
    if(f==INVALID_HANDLE_VALUE)return 0;
    DWORD len=GetFileSize(f,NULL);
    if(len==INVALID_FILE_SIZE||len>4*1024*1024){CloseHandle(f);return 0;}
    BYTE *data=xalloc(len?len:1);DWORD got=0;
    if(!data||!ReadFile(f,data,len,&got,NULL)||got!=len){xfree(data);data=NULL;len=0;}
    CloseHandle(f);*out=data;return len;
}
static void pips_backup_export(void) {
    if(!g_db)return;
    WCHAR path[MAX_PATH],tmp[MAX_PATH],pw[128]={0};
    if(!pips_file_dialog(1,path))return;
    if(!pips_backup_password(pw,0))return;
    if(!pips_temp_db(tmp)){wipe(pw,sizeof pw);return;}
    if(!pips_backup_db(tmp)){DeleteFileW(tmp);wipe(pw,sizeof pw);return;}
    HANDLE src=CreateFileW(tmp,GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,0,NULL);
    HANDLE dst=CreateFileW(path,GENERIC_WRITE,0,NULL,CREATE_ALWAYS,FILE_ATTRIBUTE_NORMAL,NULL);
    int ok=0;
    if(src!=INVALID_HANDLE_VALUE && dst!=INVALID_HANDLE_VALUE) {
        LARGE_INTEGER length={0};GetFileSizeEx(src,&length);
        DWORD rawlen=(DWORD)g_nprof*sizeof(PROF);
        BYTE *encrypted=xalloc(rawlen?rawlen:1),*ini=NULL;
        DWORD inilen=pips_ini_readall(&ini);
        PipsBackupHeader h={0};memcpy(h.magic,"PIPSBAK1",8);h.version=1;
        h.db_bytes=(unsigned long long)length.QuadPart;h.ini_bytes=inilen;h.profile_bytes=rawlen;
        if(encrypted && pips_backup_crypto(1,pw,&h,(BYTE*)g_prof,encrypted,rawlen)) {
            DWORD wrote=0;
            ok=WriteFile(dst,&h,sizeof h,&wrote,NULL)&&wrote==sizeof h;
            if(ok)ok=pips_copy_bytes(src,dst,h.db_bytes);
            if(ok&&inilen)ok=WriteFile(dst,ini,inilen,&wrote,NULL)&&wrote==inilen;
            if(ok&&rawlen)ok=WriteFile(dst,encrypted,rawlen,&wrote,NULL)&&wrote==rawlen;
        }
        if(encrypted){wipe(encrypted,rawlen);xfree(encrypted);}xfree(ini);
    }
    if(src!=INVALID_HANDLE_VALUE)CloseHandle(src);
    if(dst!=INVALID_HANDLE_VALUE)CloseHandle(dst);
    DeleteFileW(tmp);wipe(pw,sizeof pw);
    if(!ok)DeleteFileW(path);
    MessageBoxW(g_wnd,ok?L"Backup exported. Login profiles are password-encrypted.\nMonitoring history and device data are NOT encrypted.":
        L"Backup failed. No valid backup was created.",L"PIPS Backup",ok?MB_ICONINFORMATION:MB_ICONWARNING);
}
static void pips_backup_import(void) {
    if(!g_db)return;
    WCHAR path[MAX_PATH],pw[128]={0};
    if(!pips_file_dialog(0,path))return;
    HANDLE f=CreateFileW(path,GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,0,NULL);
    if(f==INVALID_HANDLE_VALUE)return;
    PipsBackupHeader h={0};DWORD n=0;
    LARGE_INTEGER filelen={0};GetFileSizeEx(f,&filelen);
    if(!ReadFile(f,&h,sizeof h,&n,NULL)||n!=sizeof h||memcmp(h.magic,"PIPSBAK1",8)||h.version!=1||
        h.profile_bytes>sizeof g_prof||h.ini_bytes>4*1024*1024||h.db_bytes>0x7FFFFFFFULL||
        (unsigned long long)filelen.QuadPart<sizeof h+h.db_bytes+h.ini_bytes+h.profile_bytes) {
        CloseHandle(f);MessageBoxW(g_wnd,L"Invalid or unsupported PIPS backup.",L"Import",MB_ICONWARNING);return;
    }
    if(!pips_backup_password(pw,1)){CloseHandle(f);return;}
    WCHAR tmpdb[MAX_PATH];if(!pips_temp_db(tmpdb)){CloseHandle(f);wipe(pw,sizeof pw);return;}
    HANDLE tmp=CreateFileW(tmpdb,GENERIC_WRITE,0,NULL,CREATE_ALWAYS,0,NULL);
    int ok=tmp!=INVALID_HANDLE_VALUE && pips_copy_bytes(f,tmp,h.db_bytes);
    if(tmp!=INVALID_HANDLE_VALUE)CloseHandle(tmp);
    BYTE *ini=xalloc(h.ini_bytes?h.ini_bytes:1),*cipher=xalloc(h.profile_bytes?h.profile_bytes:1);
    BYTE *plain=xalloc(h.profile_bytes?h.profile_bytes:1);
    if(ok&&h.ini_bytes)ok=ReadFile(f,ini,h.ini_bytes,&n,NULL)&&n==h.ini_bytes;
    if(ok&&h.profile_bytes)ok=ReadFile(f,cipher,h.profile_bytes,&n,NULL)&&n==h.profile_bytes;
    CloseHandle(f);
    if(ok)ok=ini&&cipher&&plain&&pips_backup_crypto(0,pw,&h,cipher,plain,h.profile_bytes);
    wipe(pw,sizeof pw);
    if(ok&&MessageBoxW(g_wnd,L"Replace existing PIPS settings, monitoring, history and login profiles with this backup?\n\n"
        L"The current database will first be saved as pips-before-restore.db in the data folder.",
        L"Confirm Restore",MB_YESNO|MB_ICONQUESTION)==IDYES) {
        WCHAR safety[MAX_PATH];wsprintfW(safety,L"%s\\pips-before-restore.db",g_datadir);
        if(pips_backup_db(safety)) {
            sqlite3 *source=NULL;
            if(sqlite3_open16(tmpdb,&source)==SQLITE_OK) {
                sqlite3_backup *b=sqlite3_backup_init(g_db,"main",source,"main");
                ok=0;
                if(b){ok=sqlite3_backup_step(b,-1)==SQLITE_DONE;sqlite3_backup_finish(b);}
                sqlite3_close(source);
                if(ok) {
                    const WCHAR *target=GetFileAttributesW(g_ini)!=INVALID_FILE_ATTRIBUTES?g_ini:g_ini2;
                    HANDLE output=CreateFileW(target,GENERIC_WRITE,0,NULL,CREATE_ALWAYS,0,NULL);
                    if(output==INVALID_HANDLE_VALUE)output=CreateFileW(g_ini2,GENERIC_WRITE,0,NULL,CREATE_ALWAYS,0,NULL);
                    if(output!=INVALID_HANDLE_VALUE){DWORD written=0;WriteFile(output,ini,h.ini_bytes,&written,NULL);CloseHandle(output);}
                    g_nprof=h.profile_bytes/sizeof(PROF);
                    memcpy(g_prof,plain,h.profile_bytes);
                    save_profiles();
                    g_nmon=0;g_mon_inflight=0;pips_monitor_load();refill();
                }
            }else if(source)sqlite3_close(source);
        }else ok=0;
    } else ok=0;
    if(plain){wipe(plain,h.profile_bytes);xfree(plain);}
    if(cipher){wipe(cipher,h.profile_bytes);xfree(cipher);}
    xfree(ini);DeleteFileW(tmpdb);
    MessageBoxW(g_wnd,ok?L"PIPS backup restored. Login profiles have been re-encrypted for this Windows user.":
        L"Restore was cancelled or failed. Check your password and backup file.",
        L"PIPS Restore",ok?MB_ICONINFORMATION:MB_ICONWARNING);
}
static void pips_open_data_folder(void) {
    if(g_datadir[0])ShellExecuteW(g_wnd,L"open",g_datadir,NULL,NULL,SW_SHOWNORMAL);
}
