#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <PCSC/winscard.h>
#include <PCSC/wintypes.h>

#define REALLIB "/usr/lib/aarch64-linux-gnu/libpcsclite.so.1"
static void *H;

__attribute__((constructor)) static void init(void) {
    H = dlopen(REALLIB, RTLD_NOW | RTLD_LOCAL);
}
static void *sym(const char *n) { return H ? dlsym(H, n) : NULL; }

const SCARD_IO_REQUEST g_rgSCardT0Pci  = { SCARD_PROTOCOL_T0,  sizeof(SCARD_IO_REQUEST) };
const SCARD_IO_REQUEST g_rgSCardT1Pci  = { SCARD_PROTOCOL_T1,  sizeof(SCARD_IO_REQUEST) };
const SCARD_IO_REQUEST g_rgSCardRawPci = { SCARD_PROTOCOL_RAW, sizeof(SCARD_IO_REQUEST) };

static DWORD fixproto(DWORD p) {
    p &= ~(DWORD)SCARD_PROTOCOL_RAW;
    if (p == SCARD_PROTOCOL_T0) return SCARD_PROTOCOL_T1;   /* card is T=1 only */
    if (p == 0)                 return SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1;
    return p;
}

LONG SCardConnect(SCARDCONTEXT c, LPCSTR r, DWORD sh, DWORD pr, LPSCARDHANDLE h, LPDWORD ap) {
    static LONG (*f)(SCARDCONTEXT, LPCSTR, DWORD, DWORD, LPSCARDHANDLE, LPDWORD);
    if (!f) f = sym("SCardConnect");
    DWORD p = fixproto(pr);
    LONG rc = f(c, r, sh, p, h, ap);
    if (rc != SCARD_S_SUCCESS && p != (SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1))
        rc = f(c, r, sh, SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1, h, ap);
    return rc;
}

LONG SCardReconnect(SCARDHANDLE h, DWORD sh, DWORD pr, DWORD init, LPDWORD ap) {
    static LONG (*f)(SCARDHANDLE, DWORD, DWORD, DWORD, LPDWORD);
    if (!f) f = sym("SCardReconnect");
    DWORD p = fixproto(pr);
    LONG rc = f(h, sh, p, init, ap);
    if (rc != SCARD_S_SUCCESS && p != (SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1))
        rc = f(h, sh, SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1, init, ap);
    return rc;
}

/* --- WCN card-removal debounce --------------------------------------------
 * The Dell SK-3205 over RDP redirection intermittently reports the seated card
 * absent for < 2 s (SCARD_STATE_EMPTY). That transient makes the NHS Identity
 * Agent log the pharmacist out of Spine, which stops ProScript's ETP poll and
 * does not recover. A local USB reader never produces this. When we see a
 * PRESENT -> EMPTY transition we wait up to WCN_SCARD_DEBOUNCE_MS (default
 * 3000) for the card to return; if it returns within the window we suppress the
 * transient removal so the VM never sees it. A genuine removal (card stays out
 * past the window) is reported as normal, only delayed by the window. */
static DWORD debounce_ms(void) {
    const char *e = getenv("WCN_SCARD_DEBOUNCE_MS");
    if (e && *e) { long v = atol(e); if (v >= 0 && v <= 10000) return (DWORD)v; }
    return 3000;
}
static void dbg(const char *what, const char *reader) {
    const char *p = getenv("WCN_SCARD_DEBOUNCE_LOG");
    if (!p || !*p) p = "/tmp/wcn-pcsc-debounce.log";
    FILE *fp = fopen(p, "a");
    if (!fp) return;
    time_t t = time(NULL); struct tm tm; localtime_r(&t, &tm);
    char ts[32]; strftime(ts, sizeof ts, "%Y-%m-%d %H:%M:%S", &tm);
    fprintf(fp, "%s %s reader=%s\n", ts, what, reader ? reader : "?");
    fclose(fp);
}

LONG SCardGetStatusChange(SCARDCONTEXT ctx, DWORD tout, SCARD_READERSTATE *rs, DWORD cnt) {
    static LONG (*real)(SCARDCONTEXT, DWORD, SCARD_READERSTATE *, DWORD);
    if (!real) real = (LONG (*)(SCARDCONTEXT, DWORD, SCARD_READERSTATE *, DWORD))sym("SCardGetStatusChange");
    if (!real) return SCARD_F_INTERNAL_ERROR;
    DWORD i;
    for (i = 0; i < cnt; i++)
        rs[i].dwCurrentState &= ~(DWORD)SCARD_STATE_CHANGED;
    LONG rc = real(ctx, tout, rs, cnt);
    if (rc != SCARD_S_SUCCESS) return rc;
    if (tout == 0) return rc;   /* non-blocking poll: never add latency */

    for (i = 0; i < cnt; i++) {
        if (rs[i].szReader && strcmp(rs[i].szReader, "\\\\?PnP?\\Notification") == 0)
            continue;                                   /* reader arrival channel, not a card */
        int was_present = (rs[i].dwCurrentState & SCARD_STATE_PRESENT) != 0;
        int now_empty   = (rs[i].dwEventState & SCARD_STATE_EMPTY) != 0
                          && !(rs[i].dwEventState & SCARD_STATE_PRESENT);
        int changed     = (rs[i].dwEventState & SCARD_STATE_CHANGED) != 0;
        if (was_present && now_empty && changed) {
            SCARD_READERSTATE t = rs[i];
            t.dwCurrentState = rs[i].dwEventState & ~(DWORD)SCARD_STATE_CHANGED;  /* = EMPTY */
            t.pvUserData = NULL;
            LONG rc2 = real(ctx, debounce_ms(), &t, 1);
            if (rc2 == SCARD_S_SUCCESS && (t.dwEventState & SCARD_STATE_PRESENT)) {
                /* card came back within the window -> hide the blip from the VM */
                rs[i].dwEventState = t.dwEventState & ~(DWORD)SCARD_STATE_CHANGED;
                rs[i].cbAtr = t.cbAtr;
                if (t.cbAtr <= MAX_ATR_SIZE) memcpy(rs[i].rgbAtr, t.rgbAtr, t.cbAtr);
                dbg("SUPPRESSED-phantom-removal", rs[i].szReader);
            } else {
                dbg("REAL-removal", rs[i].szReader);
            }
        }
    }
    return rc;
}

#define FWD(name, ret, params, args) \
    ret name params { static ret (*f) params; if (!f) f = sym(#name); return f args; }

FWD(SCardEstablishContext, LONG, (DWORD a, LPCVOID b, LPCVOID c, LPSCARDCONTEXT d), (a,b,c,d))
FWD(SCardReleaseContext,   LONG, (SCARDCONTEXT a), (a))
FWD(SCardIsValidContext,   LONG, (SCARDCONTEXT a), (a))
FWD(SCardDisconnect,       LONG, (SCARDHANDLE a, DWORD b), (a,b))
FWD(SCardBeginTransaction, LONG, (SCARDHANDLE a), (a))
FWD(SCardEndTransaction,   LONG, (SCARDHANDLE a, DWORD b), (a,b))
FWD(SCardStatus,           LONG, (SCARDHANDLE a, LPSTR b, LPDWORD c, LPDWORD d, LPDWORD e, LPBYTE f_, LPDWORD g), (a,b,c,d,e,f_,g))
FWD(SCardControl,          LONG, (SCARDHANDLE a, DWORD b, LPCVOID c, DWORD d, LPVOID e, DWORD f_, LPDWORD g), (a,b,c,d,e,f_,g))
FWD(SCardGetAttrib,        LONG, (SCARDHANDLE a, DWORD b, LPBYTE c, LPDWORD d), (a,b,c,d))
FWD(SCardSetAttrib,        LONG, (SCARDHANDLE a, DWORD b, LPCBYTE c, DWORD d), (a,b,c,d))
FWD(SCardTransmit,         LONG, (SCARDHANDLE a, const SCARD_IO_REQUEST *b, LPCBYTE c, DWORD d, SCARD_IO_REQUEST *e, LPBYTE f_, LPDWORD g), (a,b,c,d,e,f_,g))
FWD(SCardListReaderGroups, LONG, (SCARDCONTEXT a, LPSTR b, LPDWORD c), (a,b,c))
FWD(SCardListReaders,      LONG, (SCARDCONTEXT a, LPCSTR b, LPSTR c, LPDWORD d), (a,b,c,d))
FWD(SCardFreeMemory,       LONG, (SCARDCONTEXT a, LPCVOID b), (a,b))
FWD(SCardCancel,           LONG, (SCARDCONTEXT a), (a))
