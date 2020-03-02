package com.tencentyun;

// 使用旧版本 base64 编解码实现增强兼容性
import sun.misc.BASE64Encoder;

import java.io.UnsupportedEncodingException;
import java.security.*;
import java.nio.charset.Charset;

import java.util.Arrays;
import java.util.zip.Deflater;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.json.JSONObject;

public class TLSSigAPIv2 {
    private long sdkappid;
    private String key;

    public TLSSigAPIv2(long sdkappid, String key) {
        this.sdkappid = sdkappid;
        this.key = key;
    }

    private String hmacsha256(String identifier, long currTime, long expire, String base64Userbuf) {
        String contentToBeSigned = "TLS.identifier:" + identifier + "\n"
                + "TLS.sdkappid:" + sdkappid + "\n"
                + "TLS.time:" + currTime + "\n"
                + "TLS.expire:" + expire + "\n";
        if (null != base64Userbuf) {
            contentToBeSigned += "TLS.userbuf:" + base64Userbuf + "\n";
        }
        try {
            byte[] byteKey = key.getBytes("UTF-8");
            Mac hmac = Mac.getInstance("HmacSHA256");
            SecretKeySpec keySpec = new SecretKeySpec(byteKey, "HmacSHA256");
            hmac.init(keySpec);
            byte[] byteSig = hmac.doFinal(contentToBeSigned.getBytes("UTF-8"));
            return (new BASE64Encoder().encode(byteSig)).replaceAll("\\s*", "");
        } catch (UnsupportedEncodingException e) {
            return "";
        } catch (NoSuchAlgorithmException e) {
            return "";
        } catch (InvalidKeyException  e) {
            return "";
        }
    }

    private String genSig(String identifier, long expire, byte[] userbuf) {

        long currTime = System.currentTimeMillis()/1000;

        JSONObject sigDoc = new JSONObject();
        sigDoc.put("TLS.ver", "2.0");
        sigDoc.put("TLS.identifier", identifier);
        sigDoc.put("TLS.sdkappid", sdkappid);
        sigDoc.put("TLS.expire", expire);
        sigDoc.put("TLS.time", currTime);

        String base64UserBuf = null;
        if (null != userbuf) {
            base64UserBuf = new BASE64Encoder().encode(userbuf);
            sigDoc.put("TLS.userbuf", base64UserBuf);
        }
        String sig = hmacsha256(identifier, currTime, expire, base64UserBuf);
        if (sig.length() == 0) {
            return "";
        }
        sigDoc.put("TLS.sig", sig);
        Deflater compressor = new Deflater();
        compressor.setInput(sigDoc.toString().getBytes(Charset.forName("UTF-8")));
        compressor.finish();
        byte [] compressedBytes = new byte[2048];
        int compressedBytesLength = compressor.deflate(compressedBytes);
        compressor.end();
        return (new String(Base64URL.base64EncodeUrl(Arrays.copyOfRange(compressedBytes,
                0, compressedBytesLength)))).replaceAll("\\s*", "");
    }
    /**用于生成实时音视频(TRTC)业务进房权限加密串,具体用途用法参考TRTC文档：https://cloud.tencent.com/document/product/647/32240 
    * TRTC业务进房权限加密串需使用用户定义的userbuf
    * @brief 生成 userbuf
    * @param account 用户名
    * @param dwSdkappid sdkappid
    * @param dwAuthID  数字房间号
    * @param dwExpTime 过期时间：该权限加密串的过期时间，超时时间内拿到该签名，并且发起进房间操作，时间为有效期
    * 实际填入userBuf为：expire，过期时间,当前时间 + 有效期（单位：秒）
    * @param dwPrivilegeMap 用户权限，255表示所有权限，主播0xff，观众0xab
    * @param dwAccountType 用户类型,默认为0
    * @return byte[] userbuf
    */
    public byte[] genUserBuf(String account ,long dwAuthID, long dwExpTime ,
                             long dwPrivilegeMap ,long dwAccountType){
        //视频校验位需要用到的字段,按照网络字节序放入buf中
        /*
         cVer    unsigned char/1 版本号，填0
         wAccountLen unsigned short /2   第三方自己的帐号长度
         account wAccountLen 第三方自己的帐号字符
         dwSdkAppid  unsigned int/4  sdkappid
         dwAuthID    unsigned int/4  群组号码
         dwExpTime   unsigned int/4  过期时间 ，直接使用填入的值
         dwPrivilegeMap  unsigned int/4  权限位，主播0xff，观众0xab
         dwAccountType   unsigned int/4  第三方帐号类型
         */
        int accountLength = account.length();
        int offset = 0;
        byte[] userbuf = new byte[1+2+accountLength+4+4+4+4+4];

        //cVer
        userbuf[offset++] = 0;

        //wAccountLen
        userbuf[offset++] = (byte)((accountLength & 0xFF00) >> 8);
        userbuf[offset++] = (byte)(accountLength & 0x00FF);

        //account
        for (; offset < 3 + accountLength; ++offset) {
            userbuf[offset] = (byte)account.charAt(offset - 3);
        }

        //dwSdkAppid
        userbuf[offset++] = (byte)((sdkappid & 0xFF000000) >> 24);
        userbuf[offset++] = (byte)((sdkappid & 0x00FF0000) >> 16);
        userbuf[offset++] = (byte)((sdkappid & 0x0000FF00) >> 8);
        userbuf[offset++] = (byte)(sdkappid & 0x000000FF);

        //dwAuthId,房间号
        userbuf[offset++] = (byte)((dwAuthID & 0xFF000000) >> 24);
        userbuf[offset++] = (byte)((dwAuthID & 0x00FF0000) >> 16);
        userbuf[offset++] = (byte)((dwAuthID & 0x0000FF00) >> 8);
        userbuf[offset++] = (byte)(dwAuthID & 0x000000FF);

        //expire，过期时间,当前时间 + 有效期（单位：秒）
        long currTime = System.currentTimeMillis()/1000;
        long  expire = currTime + dwExpTime;
        userbuf[offset++] = (byte)((expire & 0xFF000000) >> 24);
        userbuf[offset++] = (byte)((expire & 0x00FF0000) >> 16);
        userbuf[offset++] = (byte)((expire & 0x0000FF00) >> 8);
        userbuf[offset++] = (byte)(expire & 0x000000FF);

        //dwPrivilegeMap，权限位
        userbuf[offset++] = (byte)((dwPrivilegeMap & 0xFF000000) >> 24);
        userbuf[offset++] = (byte)((dwPrivilegeMap & 0x00FF0000) >> 16);
        userbuf[offset++] = (byte)((dwPrivilegeMap & 0x0000FF00) >> 8);
        userbuf[offset++] = (byte)(dwPrivilegeMap & 0x000000FF);

        //dwAccountType，账户类型
        userbuf[offset++] = (byte)((dwAccountType & 0xFF000000) >> 24);
        userbuf[offset++] = (byte)((dwAccountType & 0x00FF0000) >> 16);
        userbuf[offset++] = (byte)((dwAccountType & 0x0000FF00) >> 8);
        userbuf[offset++] = (byte)(dwAccountType & 0x000000FF);

        return userbuf;
    }

    public String genSig(String identifier, long expire) {
        return genSig(identifier, expire, null);
    }
    /*
    * @param identifier 用户名
    * @param  expire  超时时间
    * @param privilege 用户权限，255表示所有权限，主播0xff，观众0xab
    * @param dwAccountType 用户类型,默认为0
    * @return byte[] userbuf
    */
    public String genSigWithUserBuf(String identifier, long expire,long roomnum, long privilege) {
        byte[] userbuf = genUserBuf(identifier,roomnum,expire,privilege,0);  //生成userbuf
        return genSig(identifier, expire, userbuf);
    }
}
