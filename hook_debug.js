Java.perform(function() {
    console.log("[*] Script loaded. Searching for classes in all ClassLoaders...");

    var hooked = false;
    var k_counter = 0;

    function makeByteArr(byteVal, len) { 
        var arr = [];
        for (var i = 0; i < len; i++) {
            arr.push(byteVal);
        }
        return Java.array('byte', arr);
    }
    
    // Fixed values matching Python debug configuration
    var FIXED_SECRET = makeByteArr(0x11, 32);
    var FIXED_K1 = makeByteArr(0x22, 32);
    var FIXED_K2 = makeByteArr(0x33, 32);
    var FIXED_IMEI = "123456789012345";

    function hook_classes(loader) {
        if (hooked) return;
        
        try {
            var UtilsAClass = loader.findClass("cn.org.bjca.signet.coss.impl.utils.a");
            if (!UtilsAClass) return;
            
            console.log("[+] Found target class in loader: " + loader);
            Java.classFactory.loader = loader;
            
            var UtilsA = Java.use('cn.org.bjca.signet.coss.impl.utils.a');
            var JeProvider = Java.use('cn.org.bjca.gaia.assemb.base.JeProvider');
            var CollaborateUtil = Java.use('cn.org.bjca.gaia.assemb.util.CollaborateUtil');
            var DeviceInfoUtil = Java.use('cn.org.bjca.signet.coss.impl.utils.DeviceInfoUtil');

            function toHex(bArr) {
                if (!bArr) return 'null';
                var str = '';
                for (var i = 0; i < bArr.length; i++) {
                    var b = bArr[i] & 0xFF;
                    if (b < 16) str += '0';
                    str += b.toString(16);
                }
                return str;
            }

            console.log("[*] Installing hooks with FIXED values...");

            // 1. Hook Random Secret Generation -> Force FIXED_SECRET
            UtilsA.a.overload('int').implementation = function(len) {
                console.log("\n[+] utils.a.a(int) [Generate Random Secret]");
                console.log("    Requested Len: " + len);
                console.log("    RETURNING FIXED SECRET (0x11...)");
                return FIXED_SECRET;
            }

            // 2. Hook ClientSecret Calc (Just logging, logic should be deterministic if inputs are fixed)
            UtilsA.a.overload('[B', '[B', '[B', 'java.lang.String').implementation = function(b1, b2, b3, s) {
                console.log("\n[+] utils.a.a [Calculate ClientSecret]");
                console.log("    Arg1 (Hash IMEI?): " + toHex(b1));
                console.log("    Arg2 (Random?):    " + toHex(b2));
                console.log("    Arg3 (Hash PIN?):  " + toHex(b3));
                var ret = this.a(b1, b2, b3, s);
                console.log("    Result (d_client): " + toHex(ret));
                return ret;
            }

            // 3. Hook k1, k2 -> Force FIXED_K1, FIXED_K2
            JeProvider.generateRangeRandom.overload('[B').implementation = function(bArr) {
                console.log("\n[+] JeProvider.generateRangeRandom [k1 or k2]");
                k_counter++;
                var ret;
                if (k_counter % 2 != 0) {
                     console.log("    RETURNING FIXED K1 (0x22...)");
                     ret = FIXED_K1;
                } else {
                     console.log("    RETURNING FIXED K2 (0x33...)");
                     ret = FIXED_K2;
                }
                return ret;
            }

            // 4. Hook Co-Sign Math (Logging)
            CollaborateUtil.serverSemSign.overload('[B', '[B', '[B').implementation = function(p, d, e) {
                console.log("\n[!!!] CollaborateUtil.serverSemSign [The Critical Math]");
                console.log("    P (SignParam):   " + toHex(p));
                console.log("    d (ClientSecret):" + toHex(d));
                console.log("    e (Hash):        " + toHex(e));
                
                var ret = this.serverSemSign(p, d, e);
                
                console.log("    Result [s1]: " + toHex(ret[0]));
                console.log("    Result [s2]: " + toHex(ret[1]));
                console.log("    Result [s3]: " + toHex(ret[2]));
                return ret;
            }
            
            // 5. Hook IMEI -> Force FIXED_IMEI
            DeviceInfoUtil.getDeviceId.implementation = function(ctx) {
                console.log("\n[+] DeviceInfoUtil.getDeviceId");
             console.log("    RETURNING FIXED IMEI: " + FIXED_IMEI);
                return FIXED_IMEI;
            }

            hooked = true;
            console.log("[*] Hooks installed successfully!");

        } catch (e) {
             // console.log(e);
        }
    }

    Java.enumerateClassLoaders({
        onMatch: function(loader) {
            hook_classes(loader);
        },
        onComplete: function() {}
    });
});
