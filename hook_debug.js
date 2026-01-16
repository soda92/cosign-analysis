Java.perform(function() {
    console.log("[*] Script loaded. Searching for classes in all ClassLoaders...");

    var hooked = false;

    function hook_classes(loader) {
        if (hooked) return;
        
        try {
            // Try to find the target class in this loader
            var UtilsAClass = loader.findClass("cn.org.bjca.signet.coss.impl.utils.a");
            if (!UtilsAClass) return;
            
            console.log("[+] Found target class in loader: " + loader);
            
            // Switch to this loader context
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

            console.log("[*] Installing hooks...");

            // 1. Hook Random Secret Generation
            UtilsA.a.overload('int').implementation = function(len) {
                var ret = this.a(len);
                console.log("\n[+] utils.a.a(int) [Generate Random Secret]");
                console.log("    Length: " + len);
                console.log("    Result: " + toHex(ret));
                return ret;
            }

            // 2. Hook ClientSecret Calc
            UtilsA.a.overload('[B', '[B', '[B', 'java.lang.String').implementation = function(b1, b2, b3, s) {
                console.log("\n[+] utils.a.a [Calculate ClientSecret]");
                console.log("    Arg1 (Hash IMEI?): " + toHex(b1));
                console.log("    Arg2 (Random?):    " + toHex(b2));
                console.log("    Arg3 (Hash PIN?):  " + toHex(b3));
                console.log("    Arg4 (Version):    " + s);
                var ret = this.a(b1, b2, b3, s);
                console.log("    Result (d_client): " + toHex(ret));
                return ret;
            }

            // 3. Hook k1, k2
            JeProvider.generateRangeRandom.overload('[B').implementation = function(bArr) {
                var ret = this.generateRangeRandom(bArr);
                console.log("\n[+] JeProvider.generateRangeRandom [k1 or k2]");
                console.log("    Result (k): " + toHex(ret));
                return ret;
            }

            // 4. Hook Co-Sign Math
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
            
            // 5. Hook IMEI
            DeviceInfoUtil.getDeviceId.implementation = function(ctx) {
                var ret = this.getDeviceId(ctx);
                console.log("\n[+] DeviceInfoUtil.getDeviceId");
                console.log("    Real IMEI sent to server: " + ret);
                return ret;
            }

            hooked = true;
            console.log("[*] Hooks installed successfully!");

        } catch (e) {
            // console.log(e);
        }
    }

    // Attempt to hook in all existing loaders
    Java.enumerateClassLoaders({
        onMatch: function(loader) {
            hook_classes(loader);
        },
        onComplete: function() {}
    });
});