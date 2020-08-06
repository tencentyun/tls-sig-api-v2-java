package com.tencentyun;

import org.junit.Test;
import org.junit.Before;
import org.junit.After;

/**
 * TLSSigAPI Tester.
 *
 * @author <Authors name>
 * @version 1.0
 * @since <pre>六月 11, 2019</pre>
 */
public class TLSSigAPITest {

    @Before
    public void before() throws Exception {
    }

    @After
    public void after() throws Exception {
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
    public void testGenSigWithUserBug() {
        TLSSigAPIv2 api = new TLSSigAPIv2(1400000000, "5bd2850fff3ecb11d7c805251c51ee463a25727bddc2385f3fa8bfee1bb93b5e");
        System.out.println(api.genPrivateMapKey("xiaojun", 180 * 86400, 10000, 255));
    }

    /**
     * Method: hmacsha256(String identifier, long currTime, long expire)
     */
    @Test
    public void testHmacsha256() throws Exception {
//TODO: Test goes here... 
/* 
try { 
   Method method = TLSSigAPI.getClass().getMethod("hmacsha256", String.class, long.class, long.class); 
   method.setAccessible(true); 
   method.invoke(<Object>, <Parameters>); 
} catch(NoSuchMethodException e) { 
} catch(IllegalAccessException e) { 
} catch(InvocationTargetException e) { 
} 
*/
    }

} 
