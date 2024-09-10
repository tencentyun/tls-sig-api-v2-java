package com.tencentyun;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

/**
 * TLSSigAPI Tester.
 *
 * @author <Authors name>
 * @version 1.0
 * @since <pre>六月 11, 2019</pre>
 */
public class TLSSigAPITest {

    @Before
    public void before() {
    }

    @After
    public void after() {
    }

    /**
     * Method: genSig(String identifier, long expire)
     */
    @Test
    public void testGenSig() {
        TLSSigAPIv2 api = new TLSSigAPIv2(1400000000, "5bd2850fff3ecb11d7c805251c51ee463a25727bddc2385f3fa8bfee1bb93b5e");
        System.out.print(api.genUserSig("xiaojun", 180 * 86400));
    }

    //使用userbuf生产privatemapkey
    @Test
    public void testGenSigWithUserBuf() {
        TLSSigAPIv2 api = new TLSSigAPIv2(1400000000, "5bd2850fff3ecb11d7c805251c51ee463a25727bddc2385f3fa8bfee1bb93b5e");
        System.out.println(api.genPrivateMapKey("xiaojun", 180 * 86400, 10000, 255));
    }

    //使用userbuf和字符串房间号生产privatemapkey
    @Test
    public void testGenSigWithUserBuf1() {
        TLSSigAPIv2 api = new TLSSigAPIv2(1400000000, "5bd2850fff3ecb11d7c805251c51ee463a25727bddc2385f3fa8bfee1bb93b5e");
        System.out.println(api.genPrivateMapKeyWithStringRoomID("xiaojun", 180 * 86400, "100000000", 255));
    }

    /**
     * Method: hmacsha256(String identifier, long currTime, long expire)
     */
    @Test
    public void testHmacsha256() {
    }

} 
