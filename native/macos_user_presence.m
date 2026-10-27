#import <Foundation/Foundation.h>
#import <LocalAuthentication/LocalAuthentication.h>
#import <Security/Security.h>
#import <dispatch/dispatch.h>

// Validate the code object that is actually bound to `pid`. This deliberately
// avoids resolving and then checking a mutable filesystem path.
// Return codes: 0 success, 10 guest lookup failed, 11 requirement/validity
// failed, 12 signing metadata did not match KakaoTalk's expected identity.
int openkakao_validate_kakaotalk_process(int pid) {
    @autoreleasepool {
        NSDictionary *attributes = @{
            (__bridge NSString *)kSecGuestAttributePid : @(pid)
        };
        SecCodeRef guest = NULL;
        OSStatus status = SecCodeCopyGuestWithAttributes(
            NULL,
            (__bridge CFDictionaryRef)attributes,
            kSecCSDefaultFlags,
            &guest);
        if (status != errSecSuccess || guest == NULL) {
            return 10;
        }

        CFStringRef requirement_text = CFSTR(
            "anchor apple generic and identifier \"com.kakao.KakaoTalkMac\"");
        SecRequirementRef requirement = NULL;
        status = SecRequirementCreateWithString(
            requirement_text, kSecCSDefaultFlags, &requirement);
        if (status != errSecSuccess || requirement == NULL) {
            CFRelease(guest);
            return 11;
        }

        status = SecCodeCheckValidity(guest, kSecCSStrictValidate, requirement);
        CFRelease(requirement);
        if (status != errSecSuccess) {
            CFRelease(guest);
            return 11;
        }

        CFDictionaryRef signing_info = NULL;
        status = SecCodeCopySigningInformation(
            guest, kSecCSSigningInformation, &signing_info);
        CFRelease(guest);
        if (status != errSecSuccess || signing_info == NULL) {
            return 12;
        }

        NSDictionary *info = (__bridge NSDictionary *)signing_info;
        NSString *identifier = info[(__bridge NSString *)kSecCodeInfoIdentifier];
        NSString *team = info[(__bridge NSString *)kSecCodeInfoTeamIdentifier];
        BOOL matches = [identifier isEqualToString:@"com.kakao.KakaoTalkMac"] &&
                       [team isEqualToString:@"L75WVXX68A"];
        CFRelease(signing_info);
        return matches ? 0 : 12;
    }
}

// Return codes are intentionally small and stable for the Rust FFI boundary:
// 0 success, 1 unavailable, 2 denied/cancelled, 3 timed out.
int openkakao_authenticate_device_owner(const char *reason_utf8) {
    @autoreleasepool {
        LAContext *context = [[LAContext alloc] init];
        NSError *availability_error = nil;
        if (![context canEvaluatePolicy:LAPolicyDeviceOwnerAuthentication
                                  error:&availability_error]) {
            return 1;
        }

        NSString *reason = [NSString stringWithUTF8String:reason_utf8];
        if (reason == nil) {
            return 1;
        }

        dispatch_semaphore_t completion = dispatch_semaphore_create(0);
        __block BOOL authenticated = NO;
        [context evaluatePolicy:LAPolicyDeviceOwnerAuthentication
                localizedReason:reason
                          reply:^(BOOL success, NSError *error) {
                              (void)error;
                              authenticated = success;
                              dispatch_semaphore_signal(completion);
                          }];

        dispatch_time_t deadline = dispatch_time(
            DISPATCH_TIME_NOW, (int64_t)(120 * NSEC_PER_SEC));
        if (dispatch_semaphore_wait(completion, deadline) != 0) {
            [context invalidate];
            return 3;
        }
        return authenticated ? 0 : 2;
    }
}

// Read one generic-password item (service/account) from the login keychain without
// ever showing a prompt. Used to fetch the signed-request HMAC key; the item's ACL
// decides which binaries may read it. The secret is copied into the caller's buffer.
// Return codes: 0 success, 1 item not found, 2 access denied / would need user
// interaction, 3 other failure, 4 buffer too small.
int openkakao_read_keychain_secret(const char *service_utf8,
                                   const char *account_utf8,
                                   unsigned char *out,
                                   size_t cap,
                                   size_t *out_len) {
    @autoreleasepool {
        if (service_utf8 == NULL || account_utf8 == NULL || out == NULL || out_len == NULL) {
            return 3;
        }
        *out_len = 0;
        NSString *service = [NSString stringWithUTF8String:service_utf8];
        NSString *account = [NSString stringWithUTF8String:account_utf8];
        if (service == nil || account == nil) {
            return 3;
        }

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
        // Fail instead of prompting (LaunchAgent sessions must never open a dialog).
        SecKeychainSetUserInteractionAllowed(FALSE);
        NSDictionary *query = @{
            (__bridge id)kSecClass : (__bridge id)kSecClassGenericPassword,
            (__bridge id)kSecAttrService : service,
            (__bridge id)kSecAttrAccount : account,
            (__bridge id)kSecReturnData : @YES,
            (__bridge id)kSecMatchLimit : (__bridge id)kSecMatchLimitOne,
            (__bridge id)kSecUseAuthenticationUI : (__bridge id)kSecUseAuthenticationUIFail,
        };
#pragma clang diagnostic pop

        CFTypeRef result = NULL;
        OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)query, &result);
        if (status == errSecItemNotFound) {
            return 1;
        }
        if (status == errSecInteractionNotAllowed || status == errSecAuthFailed ||
            status == errSecUserCanceled || status == errSecNoAccessForItem) {
            return 2;
        }
        if (status != errSecSuccess || result == NULL) {
            return 3;
        }
        NSData *data = (__bridge_transfer NSData *)result;
        if (data.length > cap) {
            return 4;
        }
        memcpy(out, data.bytes, data.length);
        *out_len = data.length;
        return 0;
    }
}
