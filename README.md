# java实现的RSA加密/解密工具


###工具说明

+ 基于bouncycastle包实现加密解密功能。

+ 提供生成public/private key对，加密/解密byte数组的功能。

+ 支持分段加密/解密长文本。

+ 暂时java只支持PKCS#1 / PKCS#8编码的版本.



### 使用流程：

1.使用openssl生成一对公钥和私钥，指定私钥长度。（linux下使用openssl工具实现）

        私钥生成： openssl genrsa -out rsa_private_key.pem 2048

        公钥生成： openssl rsa -in rsa_private_key.pem -out rsa_public_key.pem -pubout

    
    注意：以上生成的私钥编码是PKCS#1，java默认读取的是PKCS#8的版本，所以需要用openssl命令生成PKCS#8版本的私钥（不经过二次加密的）。

        代码中实现了对PKCS#1版本的密钥读取。不过为了和其他java项目保持一致，还是建议使用PKCS#8的版本。

        PKCS#8转化：  openssl pkcs8 -topk8 -in rsa_private_key.pem -out pkcs8_rsa_private_key.pem -nocrypt
  (-nocrypt指定不使用二次加密)

2.在项目中导入bouncycastle包，再粘贴RSAHelper类代码，放入指定包内。使用枚举类使其限制为单例模式。
3.通过从文件/流中读取或者set方法设置public/private key。（根据使用需要，加密加载public key，解密加载private key）
4.如果要使用长文本的加密，需要先通过set方法修改MAX_ENCRTPT_BYTE和MAX_DECRTPT_BYTE的常量，否则可能会出现类似以下的提示。
        The encoded output stream must be represented in lines of no more than 117 characters each。