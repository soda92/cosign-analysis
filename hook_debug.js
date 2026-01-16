Java.perform(function() {
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

    console.log("[*] Waiting for crypto operations...");

    // 1. Hook Random Secret Generation (Share A)
    // k.java calls utils.a.a(32) to generate random bytes.
    var UtilsA = Java.use('cn.org.bjca.signet.coss.impl.utils.a');
    UtilsA.a.overload('int').implementation = function(len) {
        var ret = this.a(len);
        console.log("\n[+] utils.a.a(int) [Generate Random Secret]");
        console.log("    Length: " + len);
        console.log("    Result: " + toHex(ret));
        return ret;
    }

    // 2. Hook Secret Scalar Calculation (XOR Logic)
    // utils.a.a(byte[], byte[], byte[], String)
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

    // 3. Hook Random Number Generator (k1, k2)
    // CollaborateUtil calls provider.generateRangeRandom to get k1, k2
    var JeProvider = Java.use('cn.org.bjca.gaia.assemb.base.JeProvider');
    JeProvider.generateRangeRandom.overload('[B').implementation = function(bArr) {
        var ret = this.generateRangeRandom(bArr);
        console.log("\n[+] JeProvider.generateRangeRandom [k1 or k2]");
        // bArr is usually null or N
        console.log("    Result (k): " + toHex(ret));
        return ret;
    }

    // 4. Hook Co-Signing Math
    var CollaborateUtil = Java.use('cn.org.bjca.gaia.assemb.util.CollaborateUtil');
    CollaborateUtil.serverSemSign.overload('[B', '[B', '[B').implementation = function(p, d, e) {
        console.log("\n[!!!] CollaborateUtil.serverSemSign [The Critical Math]");
        console.log("    P (SignParam):   " + toHex(p));
        console.log("    d (ClientSecret):" + toHex(d));
        console.log("    e (Hash):        " + toHex(e));
        
        // The two generateRangeRandom calls above will happen HERE
        
        var ret = this.serverSemSign(p, d, e);
        
        console.log("    Result [s1]: " + toHex(ret[0]));
        console.log("    Result [s2]: " + toHex(ret[1]));
        console.log("    Result [s3]: " + toHex(ret[2]));
        return ret;
    }
    
    // 5. Hook IMEI Generation to see the REAL IMEI
    var DeviceInfoUtil = Java.use('cn.org.bjca.signet.coss.impl.utils.DeviceInfoUtil');
    DeviceInfoUtil.getDeviceId.implementation = function(ctx) {
        var ret = this.getDeviceId(ctx);
        console.log("\n[+] DeviceInfoUtil.getDeviceId");
        console.log("    Real IMEI sent to server: " + ret);
        return ret;
    }
});
