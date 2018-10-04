package io.onemfive.did;

import io.onemfive.core.ServiceRequest;
import io.onemfive.data.DID;

/**
 * Revoke Identity.
 *
 * @author objectorange
 */
public class RevokeRequest extends ServiceRequest {

    public static final int DID_REQUIRED = 1;

    public DID did;
}
