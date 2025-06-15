# AntiDecryption

<div align="right">
  <a href="#english">English</a> | <a href="#chinese">中文</a>
</div>

<a id="chinese"></a>

## 中文文档

### 项目介绍

AntiDecryption 是一个专为 iOS 应用设计的防解密保护工具。它能有效防止应用被逆向工程和解密，通过多种技术手段保护您的应用安全。

### 主要特性

- **调试检测**：检测并阻止调试器附加
- **越狱环境检测**：识别常见越狱环境
- **可疑动态库检测**：检测是否加载了逆向工程常用工具
- **模拟器检测**：防止在模拟器中运行
- **网络代理检测**：识别可能用于分析网络流量的代理
- **应用篡改检测**：检测应用是否被修改
- **解密保护**：通过 Hook 系统加密函数，在不安全环境中返回假数据
- **字符串混淆**：保护敏感字符串不被静态分析
- **主动防护**：定期检查安全状态，发现异常自动退出

### 工作原理

AntiDecryption 通过 Hook 系统的 CommonCrypto 框架，拦截解密操作。当检测到可疑环境时，它会返回假数据而非真实解密结果，从而保护应用中的敏感信息。同时，它实现了多层次的安全检测机制，确保应用运行在安全的环境中。

### 使用方法

1. 将 AntiDecryption.xm 添加到您的 Theos 项目中
2. 在您的 Makefile 中添加必要的框架引用
3. 编译并将生成的动态库与您的应用集成

### 注意事项

- 本工具仅适用于真机设备，不支持模拟器
- 请确保在集成前充分测试，避免影响正常用户体验
- 建议与其他安全措施结合使用，构建多层防护

---

<a id="english"></a>

## English Documentation

### Project Introduction

AntiDecryption is a protection tool designed for iOS applications to prevent reverse engineering and decryption. It protects your app's security through various technical measures.

### Key Features

- **Debug Detection**: Detects and blocks debugger attachment
- **Jailbreak Environment Detection**: Identifies common jailbreak environments
- **Suspicious Library Detection**: Detects if reverse engineering tools are loaded
- **Simulator Detection**: Prevents running in simulators
- **Proxy Detection**: Identifies proxies that might be used for traffic analysis
- **Tampering Detection**: Detects if the application has been modified
- **Decryption Protection**: Hooks system encryption functions to return fake data in unsafe environments
- **String Obfuscation**: Protects sensitive strings from static analysis
- **Active Protection**: Periodically checks security status and automatically exits when anomalies are detected

### How It Works

AntiDecryption hooks into the system's CommonCrypto framework to intercept decryption operations. When a suspicious environment is detected, it returns fake data instead of the actual decrypted result, thereby protecting sensitive information in the application. Additionally, it implements multi-layered security detection mechanisms to ensure the application runs in a secure environment.

### Usage

1. Add AntiDecryption.xm to your Theos project
2. Add necessary framework references in your Makefile
3. Compile and integrate the generated dynamic library with your application

### Notes

- This tool is only suitable for physical devices and does not support simulators
- Please ensure thorough testing before integration to avoid affecting normal user experience
- Recommended to be used in combination with other security measures for multi-layered protection 