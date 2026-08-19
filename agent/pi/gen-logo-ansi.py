#!/usr/bin/env python3
"""Render the WCN mark as 16-colour console art using half-block characters.

No PIL on this machine, so the PNG is decoded here: zlib is in the stdlib and PNG's filter
set is small. Half blocks give two vertical pixels per character cell, so a square pixel grid
comes out with the right aspect ratio on a text console.

The physical counter console is TERM=linux — 16 colours, no truecolour — and the logo's palette
(bright cyan through to deep blue) happens to sit almost exactly on four of them.
"""
import struct, sys, zlib

SRC = sys.argv[1]
OUT_W = int(sys.argv[2]) if len(sys.argv) > 2 else 30
CROP = (400, 226, 880, 574)          # the coloured mark only; the wordmark below it is white

def load_png(path):
    data = open(path, 'rb').read()
    assert data[:8] == b'\x89PNG\r\n\x1a\n', 'not a png'
    pos, idat, pal = 8, b'', None
    while pos < len(data):
        ln, typ = struct.unpack('>I4s', data[pos:pos + 8])
        body = data[pos + 8:pos + 8 + ln]
        if typ == b'IHDR':
            w, h, depth, colour = struct.unpack('>IIBB', body[:10])
        elif typ == b'IDAT':
            idat += body
        elif typ == b'PLTE':
            pal = body
        elif typ == b'IEND':
            break
        pos += 12 + ln
    assert depth == 8, f'only 8-bit supported, got {depth}'
    nch = {0: 1, 2: 3, 3: 1, 4: 2, 6: 4}[colour]
    raw = zlib.decompress(idat)
    stride = w * nch
    out, prev, p = [], bytearray(stride), 0
    for _ in range(h):
        f = raw[p]; p += 1
        line = bytearray(raw[p:p + stride]); p += stride
        # PNG filters, all relative to the byte one pixel to the left (a) and above (b).
        if f == 1:
            for i in range(nch, stride): line[i] = (line[i] + line[i - nch]) & 255
        elif f == 2:
            for i in range(stride): line[i] = (line[i] + prev[i]) & 255
        elif f == 3:
            for i in range(stride):
                a = line[i - nch] if i >= nch else 0
                line[i] = (line[i] + ((a + prev[i]) >> 1)) & 255
        elif f == 4:
            for i in range(stride):
                a = line[i - nch] if i >= nch else 0
                b = prev[i]
                c = prev[i - nch] if i >= nch else 0
                pp = a + b - c
                pa, pb, pc = abs(pp - a), abs(pp - b), abs(pp - c)
                pr = a if (pa <= pb and pa <= pc) else (b if pb <= pc else c)
                line[i] = (line[i] + pr) & 255
        out.append(bytes(line)); prev = line
    return w, h, nch, out, pal

W, H, NCH, ROWS, PAL = load_png(SRC)

def px(x, y):
    """(r,g,b,a) at a source pixel, normalising the colour types we might meet."""
    row = ROWS[y]; i = x * NCH
    if NCH == 4: return row[i], row[i+1], row[i+2], row[i+3]
    if NCH == 3: return row[i], row[i+1], row[i+2], 255
    if NCH == 2: return row[i], row[i], row[i], row[i+1]
    if PAL:
        j = row[i] * 3; return PAL[j], PAL[j+1], PAL[j+2], 255
    return row[i], row[i], row[i], 255

x0, y0, x1, y1 = CROP
sw, sh = x1 - x0, y1 - y0
OUT_H = max(2, round(OUT_W * sh / sw))
if OUT_H % 2: OUT_H += 1                       # half blocks need an even number of pixel rows

def sample(cx, cy):
    """Box-average one output pixel. Averaging beats nearest-neighbour on thin strokes like
    these arcs, which nearest-neighbour drops out entirely at this scale."""
    px0 = x0 + cx * sw // OUT_W; px1 = max(px0 + 1, x0 + (cx + 1) * sw // OUT_W)
    py0 = y0 + cy * sh // OUT_H; py1 = max(py0 + 1, y0 + (cy + 1) * sh // OUT_H)
    r = g = b = a = n = 0
    for yy in range(py0, min(py1, H)):
        for xx in range(px0, min(px1, W)):
            pr, pg, pb, pa = px(xx, yy)
            r += pr * pa; g += pg * pa; b += pb * pa; a += pa; n += 1
    if not n or a == 0: return (0, 0, 0, 0)
    return (r // a, g // a, b // a, a // n)

# The four console colours this logo actually needs, plus black for the background.
PALETTE = {
    None: None,
    14: (0x2E, 0xE6, 0xE0),   # bright cyan  - the light end of the gradient
    6:  (0x17, 0x9A, 0xA8),   # cyan         - the mid tones
    12: (0x2A, 0x6F, 0xC4),   # bright blue  - the darker arcs
    4:  (0x1B, 0x4F, 0x8F),   # blue         - the deepest blue and the dots
}

def nearest(rgba):
    r, g, b, a = rgba
    if a < 60: return None                     # transparent -> terminal background
    best, bd = None, 1 << 30
    for code, ref in PALETTE.items():
        if ref is None: continue
        d = (r - ref[0]) ** 2 + (g - ref[1]) ** 2 + (b - ref[2]) ** 2
        if d < bd: best, bd = code, d
    return best

# The physical counter console is the Linux framebuffer VT, which reliably renders only the 16
# standard SGR colours and only the 8 non-bright ones as a BACKGROUND. 256-colour (38;5;n) and
# bright backgrounds are silently wrong there. So map to plain SGR foregrounds and never set a
# coloured background — where a cell's two halves differ, the top wins as a full block. On a
# logo that costs a couple of edge pixels and buys correctness on the only screen that matters.
SGR = {14: '96', 6: '36', 12: '94', 4: '34'}    # brightcyan / cyan / brightblue / blue
def fg(c): return f'\033[{SGR[c]}m'

lines = []
for cy in range(0, OUT_H, 2):
    s = ''
    for cx in range(OUT_W):
        top = nearest(sample(cx, cy))
        bot = nearest(sample(cx, cy + 1))
        if top is None and bot is None: s += '\033[0m '
        elif top is not None and bot is None: s += f'\033[0m{fg(top)}▀'      # upper half
        elif top is None and bot is not None: s += f'\033[0m{fg(bot)}▄'      # lower half
        elif top == bot: s += f'\033[0m{fg(top)}█'                            # full block
        else: s += f'\033[0m{fg(top)}▀'                                       # top wins
    lines.append(s + '\033[0m')

print('\n'.join(lines))
print(f'\n[{OUT_W} cols x {len(lines)} rows]', file=sys.stderr)
