package test.com.tencentyun; 

import com.tencentyun.TLSSigAPI;
import org.junit.Test;
import org.junit.Before; 
import org.junit.After; 

/** 
* TLSSigAPI Tester. 
* 
* @author <Authors name> 
* @since <pre>六月 11, 2019</pre> 
* @version 1.0 
*/ 
public class TLSSigAPITest { 

@Before
public void before() throws Exception { 
} 

@After
public void after() throws Exception { 
} 

/** 
* 
* Method: genSig(String identifier, long expire) 
* 
*/ 
@Test
public void testGenSig() throws Exception {
    TLSSigAPI api = new TLSSigAPI(1400000000, "5bd2850fff3ecb11d7c805251c51ee463a25727bddc2385f3fa8bfee1bb93b5e");
    System.out.print(api.genSig("xiaojun", 180*86400));
} 


/** 
* 
* Method: hmacsha256(String identifier, long currTime, long expire) 
* 
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
