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
    public byte[] genUserBuf(String account ,long dwAuthID, long dwExpTime ,
                             long dwPrivilegeMap ,long dwAccountType){
        //视频校验位需要用到的字段
        /*
         cVer    unsigned char/1 版本号，填0
         wAccountLen unsigned short /2   第三方自己的帐号长度
         buffAccount wAccountLen 第三方自己的帐号字符
         dwSdkAppid  unsigned int/4  sdkappid
         dwRoomId    unsigned int/4  群组号码
         dwExpTime   unsigned int/4  过期时间 （当前时间 + 有效期（单位：秒，建议300秒））
         dwPrivilegeMap  unsigned int/4  权限位
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

        //buffAccount
        for (; offset < 3 + accountLength; ++offset) {
            userbuf[offset] = (byte)account.charAt(offset - 3);
        }

        //dwSdkAppid
        userbuf[offset++] = (byte)((sdkappid & 0xFF000000) >> 24);
        userbuf[offset++] = (byte)((sdkappid & 0x00FF0000) >> 16);
        userbuf[offset++] = (byte)((sdkappid & 0x0000FF00) >> 8);
        userbuf[offset++] = (byte)(sdkappid & 0x000000FF);

        //dwAuthId
        userbuf[offset++] = (byte)((dwAuthID & 0xFF000000) >> 24);
        userbuf[offset++] = (byte)((dwAuthID & 0x00FF0000) >> 16);
        userbuf[offset++] = (byte)((dwAuthID & 0x0000FF00) >> 8);
        userbuf[offset++] = (byte)(dwAuthID & 0x000000FF);

        //dwExpTime
        userbuf[offset++] = (byte)((dwExpTime & 0xFF000000) >> 24);
        userbuf[offset++] = (byte)((dwExpTime & 0x00FF0000) >> 16);
        userbuf[offset++] = (byte)((dwExpTime & 0x0000FF00) >> 8);
        userbuf[offset++] = (byte)(dwExpTime & 0x000000FF);

        //dwPrivilegeMap
        userbuf[offset++] = (byte)((dwPrivilegeMap & 0xFF000000) >> 24);
        userbuf[offset++] = (byte)((dwPrivilegeMap & 0x00FF0000) >> 16);
        userbuf[offset++] = (byte)((dwPrivilegeMap & 0x0000FF00) >> 8);
        userbuf[offset++] = (byte)(dwPrivilegeMap & 0x000000FF);

        //dwAccountType
        userbuf[offset++] = (byte)((dwAccountType & 0xFF000000) >> 24);
        userbuf[offset++] = (byte)((dwAccountType & 0x00FF0000) >> 16);
        userbuf[offset++] = (byte)((dwAccountType & 0x0000FF00) >> 8);
        userbuf[offset++] = (byte)(dwAccountType & 0x000000FF);

        return userbuf;
    }

    public String genSig(String identifier, long expire) {
        return genSig(identifier, expire, null);
    }

    public String genSigWithUserBuf(String identifier, long expire, byte[] userbuf) {
        return genSig(identifier, expire, userbuf);
    }
}
