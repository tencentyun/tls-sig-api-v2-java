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

    private String genUserSig(String userid, long expire, byte[] userbuf) {

        long currTime = System.currentTimeMillis()/1000;

        JSONObject sigDoc = new JSONObject();
        sigDoc.put("TLS.ver", "2.0");
        sigDoc.put("TLS.identifier", userid);
        sigDoc.put("TLS.sdkappid", sdkappid);
        sigDoc.put("TLS.expire", expire);
        sigDoc.put("TLS.time", currTime);

        String base64UserBuf = null;
        if (null != userbuf) {
            base64UserBuf = new BASE64Encoder().encode(userbuf);
            sigDoc.put("TLS.userbuf", base64UserBuf);
        }
        String sig = hmacsha256(userid, currTime, expire, base64UserBuf);
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
    * 生成 userbuf
    * @param account 用户名
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
    /**
     *【功能说明】用于签发 TRTC 和 IM 服务中必须要使用的 UserSig 鉴权票据
     *
     *【参数说明】
     * @param userid - 用户id，限制长度为32字节，只允许包含大小写英文字母（a-zA-Z）、数字（0-9）及下划线和连词符。
     * @param expire - UserSig 票据的过期时间，单位是秒，比如 86400 代表生成的 UserSig 票据在一天后就无法再使用了。
     * @return usersig -生成的签名
     */
    public String genUserSig(String userid, long expire) {
        return genUserSig(userid, expire, null);
    }

    /**
     *【功能说明】
     * 用于签发 TRTC 进房参数中可选的 PrivateMapKey 权限票据。
     * PrivateMapKey 需要跟 UserSig 一起使用，但 PrivateMapKey 比 UserSig 有更强的权限控制能力：
     *  - UserSig 只能控制某个 UserID 有无使用 TRTC 服务的权限，只要 UserSig 正确，其对应的 UserID 可以进出任意房间。
     *  - PrivateMapKey 则是将 UserID 的权限控制的更加严格，包括能不能进入某个房间，能不能在该房间里上行音视频等等。
     * 如果要开启 PrivateMapKey 严格权限位校验，需要在【实时音视频控制台】/【应用管理】/【应用信息】中打开“启动权限密钥”开关。
     *
     *【参数说明】
     * @param userid - 用户id，限制长度为32字节，只允许包含大小写英文字母（a-zA-Z）、数字（0-9）及下划线和连词符。
     * @param expire - PrivateMapKey 票据的过期时间，单位是秒，比如 86400 生成的 PrivateMapKey 票据在一天后就无法再使用了。
     * @param roomid - 房间号，用于指定该 userid 可以进入的房间号
     * @param privilegeMap - 权限位，使用了一个字节中的 8 个比特位，分别代表八个具体的功能权限开关：
     *  - 第 1 位：0000 0001 = 1，创建房间的权限
     *  - 第 2 位：0000 0010 = 2，加入房间的权限
     *  - 第 3 位：0000 0100 = 4，发送语音的权限
     *  - 第 4 位：0000 1000 = 8，接收语音的权限
     *  - 第 5 位：0001 0000 = 16，发送视频的权限
     *  - 第 6 位：0010 0000 = 32，接收视频的权限
     *  - 第 7 位：0100 0000 = 64，发送辅路（也就是屏幕分享）视频的权限
     *  - 第 8 位：1000 0000 = 200，接收辅路（也就是屏幕分享）视频的权限
     *  - privilegeMap == 1111 1111 == 255 代表该 userid 在该 roomid 房间内的所有功能权限。
     *  - privilegeMap == 0010 1010 == 42  代表该 userid 拥有加入房间和接收音视频数据的权限，但不具备其他权限。
     * @return usersig - 生成带userbuf的签名
     */
    public String genPrivateMapKey(String userid, long expire,long roomid, long privilegeMap) {
        byte[] userbuf = genUserBuf(userid,roomid,expire,privilegeMap,0);  //生成userbuf
        return genUserSig(userid, expire, userbuf);
    }
}
