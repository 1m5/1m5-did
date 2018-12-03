package io.onemfive.did;

import io.onemfive.core.ServiceRequest;

public class VerifyHashRequest extends ServiceRequest {

    public static int UNKNOWN_HASH_ALGORITHM = 1;
    public static int INVALID_KEY_SPEC = 2;

    // Request
    public String content;
    public String hashToVerify;
    public boolean isShort = false; // full is default
    // Result
    public boolean isAMatch;
}
