// AntiDecryption - 防止iOS应用被解密
// 作者：MacXK

#if TARGET_OS_SIMULATOR
#error 不支持模拟器，请使用真实的iOS设备
#endif

#import <Foundation/Foundation.h>
#import <mach-o/dyld.h>
#import <dlfcn.h>
#import <sys/sysctl.h>
#import <sys/stat.h>
#import <sys/types.h>
#import <sys/socket.h>
#import <netinet/in.h>
#import <arpa/inet.h>
#import <ifaddrs.h>
#import <mach/mach.h>
#import <mach/mach_host.h>
#import <pthread.h>
#import <objc/runtime.h>
#import <UIKit/UIKit.h>
#import <CommonCrypto/CommonCrypto.h>
#import <execinfo.h>

#define ADLog(fmt, ...) NSLog(@"[AntiDecryption] " fmt, ##__VA_ARGS__)

static BOOL isBeingDebugged() {
    int name[4] = {CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()};
    struct kinfo_proc info;
    size_t info_size = sizeof(info);
    
    if (sysctl(name, 4, &info, &info_size, NULL, 0) == -1) {
        return NO;
    }
    
    return ((info.kp_proc.p_flag & P_TRACED) != 0);
}

static BOOL isJailbroken() {
    NSArray *jailbreakPaths = @[
        @"/Applications/Cydia.app",
        @"/Library/MobileSubstrate/MobileSubstrate.dylib",
        @"/bin/bash",
        @"/usr/sbin/sshd",
        @"/etc/apt",
        @"/private/var/lib/apt"
    ];
    
    for (NSString *path in jailbreakPaths) {
        if ([[NSFileManager defaultManager] fileExistsAtPath:path]) {
            return YES;
        }
    }
    
    return NO;
}

static BOOL hasSuspiciousDylibs() {
    uint32_t count = _dyld_image_count();
    for (uint32_t i = 0; i < count; i++) {
        const char *name = _dyld_get_image_name(i);
        NSString *imageName = [NSString stringWithUTF8String:name];
        
        if ([imageName containsString:@"FridaGadget"] ||
            [imageName containsString:@"Substrate"] ||
            [imageName containsString:@"cycript"] ||
            [imageName containsString:@"cynject"] ||
            [imageName containsString:@"libcycript"]) {
            return YES;
        }
    }
    
    return NO;
}

static BOOL isRunningInEmulator() {
    #if TARGET_IPHONE_SIMULATOR
        return YES;
    #else
        NSString *modelIdentifier = [[UIDevice currentDevice] model];
        return [modelIdentifier containsString:@"Simulator"];
    #endif
}

static BOOL hasAntiDebuggingTools() {
    void *handle = dlopen("/usr/lib/libc.dylib", RTLD_NOW);
    if (handle) {
        dlclose(handle);
        return YES;
    }
    return NO;
}

static BOOL isProxyEnabled() {
    NSDictionary *proxySettings = (__bridge NSDictionary *)(CFNetworkCopySystemProxySettings());
    NSArray *proxies = (__bridge NSArray *)(CFNetworkCopyProxiesForURL(
        (__bridge CFURLRef)([NSURL URLWithString:@"https://www.apple.com"]),
        (__bridge CFDictionaryRef)(proxySettings)
    ));
    
    NSDictionary *settings = proxies.firstObject;
    return ![settings[@"kCFProxyTypeKey"] isEqualToString:@"kCFProxyTypeNone"];
}

static BOOL isAppTampered() {
    NSString *bundlePath = [[NSBundle mainBundle] bundlePath];
    NSDictionary *attributes = [[NSFileManager defaultManager] attributesOfItemAtPath:bundlePath error:nil];
    NSDate *creationDate = [attributes fileCreationDate];
    
    NSTimeInterval timeDifference = [[NSDate date] timeIntervalSinceDate:creationDate];
    if (timeDifference > 3600) {
        return YES;
    }
    
    return NO;
}

static void preventPtraceAttachment() {
    typedef int (*ptrace_ptr_t)(int _request, pid_t _pid, caddr_t _addr, int _data);
    ptrace_ptr_t ptrace_ptr = (ptrace_ptr_t)dlsym(RTLD_SELF, "ptrace");
    if (ptrace_ptr) {
        ptrace_ptr(31, 0, 0, 0);
    }
}

static void checkAndExit() {
    if (isBeingDebugged() || isJailbroken() || hasSuspiciousDylibs() || 
        isRunningInEmulator() || hasAntiDebuggingTools() || isProxyEnabled() || 
        isAppTampered()) {
        ADLog(@"检测到不安全环境，应用将退出");
        exit(0);
    }
}

static NSString *obfuscateString(NSString *input) {
    NSMutableString *output = [NSMutableString string];
    for (NSUInteger i = 0; i < input.length; i++) {
        unichar c = [input characterAtIndex:i];
        [output appendFormat:@"%C", static_cast<unichar>(c ^ 0x1F)];
    }
    return output;
}

static NSString *deobfuscateString(NSString *input) {
    return obfuscateString(input);
}

static void setupPeriodicChecks() {
    dispatch_source_t timer = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0));
    dispatch_source_set_timer(timer, dispatch_time(DISPATCH_TIME_NOW, 0), 2 * NSEC_PER_SEC, 0.1 * NSEC_PER_SEC);
    dispatch_source_set_event_handler(timer, ^{
        checkAndExit();
    });
    dispatch_resume(timer);
}

static void generateFakeData(void *buffer, size_t size) {
    uint8_t *byteBuffer = (uint8_t *)buffer;
    for (size_t i = 0; i < size; i++) {
        byteBuffer[i] = (i % 256) ^ 0x55;
    }
}

static NSString *generateFakeText(size_t length) {
    NSString *fakeMessage = @"此内容已被保护，无法解密。请联系应用开发者获取授权。";
    NSMutableString *result = [NSMutableString string];
    
    while (result.length < length) {
        [result appendString:fakeMessage];
    }
    
    if (result.length > length) {
        return [result substringToIndex:length];
    }
    
    return result;
}

static BOOL isCallStackSuspicious() {
    void *callstack[128];
    int frames = backtrace(callstack, 128);
    char **strs = backtrace_symbols(callstack, frames);
    
    BOOL suspicious = NO;
    for (int i = 0; i < frames; i++) {
        NSString *frame = [NSString stringWithUTF8String:strs[i]];
        if ([frame containsString:@"frida"] || 
            [frame containsString:@"Substrate"] ||
            [frame containsString:@"cycript"] ||
            [frame containsString:@"dumpdecrypted"]) {
            suspicious = YES;
            break;
        }
    }
    
    free(strs);
    return suspicious;
}

%hook NSData

- (NSData *)AES128DecryptWithKey:(NSString *)key iv:(NSString *)iv {
    if (isCallStackSuspicious()) {
        ADLog(@"检测到可疑的AES解密调用");
        NSString *fakeText = generateFakeText(self.length);
        NSData *fakeData = [fakeText dataUsingEncoding:NSUTF8StringEncoding];
        return fakeData;
    }
    return %orig;
}

%end

static CCCryptorStatus (*original_CCCrypt)(
    CCOperation op, CCAlgorithm alg, CCOptions options,
    const void *key, size_t keyLength, const void *iv,
    const void *dataIn, size_t dataInLength, void *dataOut,
    size_t dataOutAvailable, size_t *dataOutMoved);

static CCCryptorStatus hooked_CCCrypt(
    CCOperation op, CCAlgorithm alg, CCOptions options,
    const void *key, size_t keyLength, const void *iv,
    const void *dataIn, size_t dataInLength, void *dataOut,
    size_t dataOutAvailable, size_t *dataOutMoved) {
    
    if (op == kCCDecrypt) {
        if (isCallStackSuspicious() || isBeingDebugged() || isJailbroken() || hasSuspiciousDylibs()) {
            ADLog(@"检测到可疑的解密调用，返回假数据");
            
            generateFakeData(dataOut, dataOutAvailable);
            
            if (dataOutMoved) {
                *dataOutMoved = dataOutAvailable;
            }
            
            return kCCSuccess;
        }
    }
    
    return original_CCCrypt(op, alg, options, key, keyLength, iv, dataIn, dataInLength, dataOut, dataOutAvailable, dataOutMoved);
}

static CCCryptorStatus (*original_CCCryptorCreate)(
    CCOperation op, CCAlgorithm alg, CCOptions options,
    const void *key, size_t keyLength, const void *iv,
    CCCryptorRef *cryptorRef);

static CCCryptorStatus hooked_CCCryptorCreate(
    CCOperation op, CCAlgorithm alg, CCOptions options,
    const void *key, size_t keyLength, const void *iv,
    CCCryptorRef *cryptorRef) {
    
    if (op == kCCDecrypt) {
        if (isCallStackSuspicious() || isBeingDebugged() || isJailbroken() || hasSuspiciousDylibs()) {
            ADLog(@"检测到可疑的解密器创建，返回失败");
            return kCCParamError;
        }
    }
    
    return original_CCCryptorCreate(op, alg, options, key, keyLength, iv, cryptorRef);
}

static CCCryptorStatus (*original_CCCryptorUpdate)(
    CCCryptorRef cryptorRef, const void *dataIn,
    size_t dataInLength, void *dataOut,
    size_t dataOutAvailable, size_t *dataOutMoved);

static CCCryptorStatus hooked_CCCryptorUpdate(
    CCCryptorRef cryptorRef, const void *dataIn,
    size_t dataInLength, void *dataOut,
    size_t dataOutAvailable, size_t *dataOutMoved) {
    
    if (isCallStackSuspicious() || isBeingDebugged() || isJailbroken() || hasSuspiciousDylibs()) {
        ADLog(@"检测到可疑的解密更新操作，返回假数据");
        
        generateFakeData(dataOut, dataOutAvailable);
        
        if (dataOutMoved) {
            *dataOutMoved = dataInLength < dataOutAvailable ? dataInLength : dataOutAvailable;
        }
        
        return kCCSuccess;
    }
    
    return original_CCCryptorUpdate(cryptorRef, dataIn, dataInLength, dataOut, dataOutAvailable, dataOutMoved);
}

static CCCryptorStatus (*original_CCCryptorFinal)(
    CCCryptorRef cryptorRef, void *dataOut,
    size_t dataOutAvailable, size_t *dataOutMoved);

static CCCryptorStatus hooked_CCCryptorFinal(
    CCCryptorRef cryptorRef, void *dataOut,
    size_t dataOutAvailable, size_t *dataOutMoved) {
    
    if (isCallStackSuspicious() || isBeingDebugged() || isJailbroken() || hasSuspiciousDylibs()) {
        ADLog(@"检测到可疑的解密完成操作，返回假数据");
        
        generateFakeData(dataOut, dataOutAvailable);
        
        if (dataOutMoved) {
            *dataOutMoved = dataOutAvailable;
        }
        
        return kCCSuccess;
    }
    
    return original_CCCryptorFinal(cryptorRef, dataOut, dataOutAvailable, dataOutMoved);
}

%ctor {
    @autoreleasepool {
        ADLog(@"AntiDecryption 已加载 - 解密保护激活");
        
        preventPtraceAttachment();
        
        checkAndExit();
        
        setupPeriodicChecks();
        
        NSString *sensitive = @"这是敏感数据";
        NSString *obfuscated = obfuscateString(sensitive);
        NSString *restored = deobfuscateString(obfuscated);
        ADLog(@"混淆测试: %@ -> %@ -> %@", sensitive, obfuscated, restored);
        
        MSHookFunction((void *)CCCrypt, (void *)hooked_CCCrypt, (void **)&original_CCCrypt);
        MSHookFunction((void *)CCCryptorCreate, (void *)hooked_CCCryptorCreate, (void **)&original_CCCryptorCreate);
        MSHookFunction((void *)CCCryptorUpdate, (void *)hooked_CCCryptorUpdate, (void **)&original_CCCryptorUpdate);
        MSHookFunction((void *)CCCryptorFinal, (void *)hooked_CCCryptorFinal, (void **)&original_CCCryptorFinal);
        
        ADLog(@"CommonCrypto解密函数已被Hook");
    }
}
