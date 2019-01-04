package io.onemfive.did;

import io.onemfive.core.ServiceRequest;
import io.onemfive.data.Hash;

public class HashRequest extends ServiceRequest {

    public static int UNKNOWN_HASH_ALGORITHM = 1;
    public static int INVALID_KEY_SPEC = 2;
    // Request
    public String contentToHash;
    public boolean generateFullHash = true; // default
    public boolean generateShortHash = true; // default
    // Result
    public Hash fullHash;
    public Hash shortHash;
}
