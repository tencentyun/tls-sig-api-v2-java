## 说明
本项目为 tls-sig-api-v2 版本的 java 实现，之前非对称密钥无法使用此版本 api，如需使用请查看[这里](https://github.com/tencentyun/tls-sig-api-java)。

## 集成
### maven
``` xml
<dependencies>
    <dependency>
        <groupId>com.github.tencentyun</groupId>
        <artifactId>tls-sig-api-v2</artifactId>
        <version>1.1</version>
    </dependency>
</dependencies>
```

### gradle
```
dependencies {
    compile 'com.github.tencentyun:tls-sig-api-v2:1.1'
}
```

### 源码
``` shell
./gradlew -b user_build.gradle build
```
生成的 jar 在 `build/libs` 下面可以找到。依赖 org.json 自行下载即可。

## 使用
``` java
import com.tencentyun.TLSSigAPIv2;

TLSSigAPIv2 api = new TLSSigAPIv2(1400000000, "5bd2850fff3ecb11d7c805251c51ee463a25727bddc2385f3fa8bfee1bb93b5e");
System.out.print(api.genSig("xiaojun", 180*86400));
```