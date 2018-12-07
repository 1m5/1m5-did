package io.onemfive.did;

import io.onemfive.core.*;
import io.onemfive.core.keyring.AuthNRequest;
import io.onemfive.core.keyring.GenerateKeyRingCollectionsRequest;
import io.onemfive.did.dao.LoadDIDDAO;
import io.onemfive.did.dao.SaveDIDDAO;
import io.onemfive.data.DID;
import io.onemfive.data.Envelope;
import io.onemfive.data.Route;
import io.onemfive.data.util.DLC;
import io.onemfive.data.util.HashUtil;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.*;
import java.util.logging.Logger;
import java.util.regex.Pattern;

import static io.onemfive.did.HashRequest.UNKNOWN_HASH_ALGORITHM;

/**
 * Decentralized IDentifier (DID) Service
 *
 * @author objectorange
 */
public class DIDService extends BaseService {

    private static final Logger LOG = Logger.getLogger(DIDService.class.getName());

    public static final String OPERATION_VERIFY = "VERIFY";
    public static final String OPERATION_AUTHENTICATE = "AUTHENTICATE";
    public static final String OPERATION_SAVE = "SAVE";
    public static final String OPERATION_AUTHENTICATE_CREATE = "AUTHENTICATE_CREATE";
    public static final String OPERATION_REVOKE = "REVOKE";
    public static final String OPERATION_HASH = "HASH";
    public static final String OPERATION_VERIFY_HASH = "VERIFY_HASH";
    public static final String OPERATION_GET_LOCAL_DID = "GET_LOCAL_DID";
    public static final String OPERATION_ADD_CONTACT = "ADD_CONTACT";
    public static final String OPERATION_GET_CONTACT = "GET_CONTACT";

    private static final Pattern layout = Pattern.compile("\\$31\\$(\\d\\d?)\\$(.{43})");

    private static SecureRandom random = new SecureRandom();

    private DID localDefaultDID;
    private Map<String,DID> localUserDIDs = new HashMap<>();
    private Map<String,DID> contacts = new HashMap<>();

    public DIDService() {}

    public DIDService(MessageProducer producer, ServiceStatusListener serviceStatusListener) {
        super(producer, serviceStatusListener);
    }

    @Override
    public void handleDocument(Envelope e) {
        handleAll(e);
    }

    @Override
    public void handleEvent(Envelope e) {
        handleAll(e);
    }

    @Override
    public void handleHeaders(Envelope e) {
        handleAll(e);
    }

    private void handleAll(Envelope e) {
        Route route = e.getRoute();
        switch(route.getOperation()) {
            case OPERATION_GET_LOCAL_DID: {
                LOG.info("Received get DID request.");
                GetLocalDIDRequest r = (GetLocalDIDRequest)DLC.getData(GetLocalDIDRequest.class,e);
                if(r == null) {
                    r = new GetLocalDIDRequest();
                    r.errorCode = GetLocalDIDRequest.REQUEST_REQUIRED;
                    DLC.addData(GetLocalDIDRequest.class,r,e);
                    break;
                }
                if(r.did == null) {
                    r.errorCode = GetLocalDIDRequest.DID_REQUIRED;
                    break;
                }
                if(r.did.getUsername() == null) {
                    r.errorCode = GetLocalDIDRequest.DID_USERNAME_REQUIRED;
                    break;
                }
                r.did = getLocalDID(r);
                break;
            }
            case OPERATION_ADD_CONTACT: {
                addContact(e);
                break;
            }
            case OPERATION_GET_CONTACT: {
                getContact(e);
                break;
            }
            case OPERATION_VERIFY: {
                e.setDID(verify(e.getDID()));
                break;
            }
            case OPERATION_AUTHENTICATE: {
                LOG.info("Received authn DID request.");
                AuthenticateDIDRequest r = (AuthenticateDIDRequest)DLC.getData(AuthenticateDIDRequest.class,e);
                if(r == null) {
                    r = new AuthenticateDIDRequest();
                    r.errorCode = AuthenticateDIDRequest.REQUEST_REQUIRED;
                    DLC.addData(AuthenticateDIDRequest.class,r,e);
                    break;
                }
                if(r.did == null) {
                    r.errorCode = AuthenticateDIDRequest.DID_REQUIRED;
                    break;
                }
                if(r.did.getUsername() == null) {
                    r.errorCode = AuthenticateDIDRequest.DID_USERNAME_REQUIRED;
                    break;
                }
                if(r.did.getPassphrase() == null) {
                    r.errorCode = AuthenticateDIDRequest.DID_PASSPHRASE_REQUIRED;
                    break;
                }
                authenticate(r);
                if(r.did.getAuthenticated()) {
                    e.setDID(r.did);
                    AuthNRequest ar = (AuthNRequest)DLC.getData(AuthNRequest.class,e);
                    if(ar!=null && ar.publicKey!=null)
                        r.did.addPublicKey(ar.publicKey);
                }
                break;
            }
            case OPERATION_SAVE: {
                LOG.info("Received save DID request.");
                DID did = (DID)DLC.getData(DID.class,e);
                GenerateKeyRingCollectionsRequest gkr = (GenerateKeyRingCollectionsRequest) DLC.getData(GenerateKeyRingCollectionsRequest.class,e);
                if(gkr!=null && gkr.publicKey!=null){
                    LOG.info("LoadKeyRingsRequest found in envelope...updating DID...");
                    did.addPublicKey(gkr.publicKey);
                }
                e.setDID(save(did));
                break;
            }
            case OPERATION_AUTHENTICATE_CREATE: {
                AuthenticateDIDRequest r = (AuthenticateDIDRequest)DLC.getData(AuthenticateDIDRequest.class,e);
                authenticateOrCreate(r);
                break;
            }
            case OPERATION_REVOKE: {
                LOG.warning("REVOKE not implemented.");
                break;
            }
            case OPERATION_HASH: {
                HashRequest r = (HashRequest)DLC.getData(HashRequest.class,e);
                try {
                    if(r.generateFullHash)
                        r.fullHash = HashUtil.generateHash(r.contentToHash);
                    if(r.generateShortHash)
                        r.shortHash = HashUtil.generateShortHash(r.contentToHash);
                } catch (NoSuchAlgorithmException e1) {
                    r.errorCode = UNKNOWN_HASH_ALGORITHM;
                }
                break;
            }
            case OPERATION_VERIFY_HASH:{
                VerifyHashRequest r = (VerifyHashRequest)DLC.getData(VerifyHashRequest.class,e);
                try {
                    if(r.isShort) {
                        r.isAMatch = HashUtil.verifyShortHash(r.content.getBytes(), r.hashToVerify);
                    } else {
                        r.isAMatch = HashUtil.verifyHash(r.content, r.hashToVerify);
                    }
                } catch (NoSuchAlgorithmException e1) {
                    r.errorCode = UNKNOWN_HASH_ALGORITHM;
                }
                break;
            }
            default: deadLetter(e); // Operation not supported
        }
    }

    private DID getLocalDID(io.onemfive.did.GetLocalDIDRequest r) {
        if(localUserDIDs.containsKey(r.did.getUsername()))
            return localUserDIDs.get(r.did.getUsername());
        if(r.did.getPassphrase() == null) {
            r.errorCode = io.onemfive.did.GetLocalDIDRequest.DID_PASSPHRASE_REQUIRED;
            return r.did;
        }
        if(r.did.getPassphraseHashAlgorithm() == null) {
            r.errorCode = io.onemfive.did.GetLocalDIDRequest.DID_PASSPHRASE_HASH_ALGORITHM_UNKNOWN;
            return r.did;
        }
        return save(r.did);
    }

    private void addContact(Envelope e) {

    }

    private void getContact(Envelope e) {

    }

    private DID verify(DID did) {
        LOG.info("Received verify DID request.");
        LoadDIDDAO dao = new LoadDIDDAO(infoVaultDB, did);
        dao.execute();
        DID didLoaded = dao.getLoadedDID();
        if(didLoaded != null && did.getUsername() != null && did.getUsername().equals(didLoaded.getUsername())) {
            didLoaded.setVerified(true);
            LOG.info("DID verification successful.");
            return didLoaded;
        } else {
            did.setVerified(false);
            LOG.info("DID verification unsuccessful.");
            return did;
        }
    }

    /**
     * Saves and returns DID generating passphrase hash if none exists.
     * @param did DID
     */
    private DID save(DID did) {
        if(did.getPassphraseHash() == null) {
            LOG.info("Hashing passphrase...");
            try {
                did.setPassphraseHash(HashUtil.generateHash(did.getPassphrase()));
                // ensure passphrase is cleared
                did.setPassphrase(null);
            } catch (NoSuchAlgorithmException e) {
                LOG.warning("Hashing Algorithm not supported while saving DID\n" + e.getLocalizedMessage());
                return did;
            }
        }
        LOG.info("Saving DID...");
        SaveDIDDAO dao = new SaveDIDDAO(infoVaultDB, did, true);
        dao.execute();
        if(dao.getException() != null) {
            LOG.warning("Create DID threw exception: "+dao.getException().getLocalizedMessage());
        }
        LOG.info("DID saved.");
        return did;
    }

    /**
     * Authenticates passphrase
     * @param r AuthenticateDIDRequest
     */
    private void authenticate(AuthenticateDIDRequest r) {
        LoadDIDDAO dao = new LoadDIDDAO(infoVaultDB, r.did);
        dao.execute();
        DID loadedDID = dao.getLoadedDID();
        if(loadedDID == null || loadedDID.getUsername() == null || loadedDID.getUsername().isEmpty()) {
            r.errorCode = AuthenticateDIDRequest.DID_USERNAME_UNKNOWN;
            r.did.setAuthenticated(false);
            return;
        }
        if(!r.did.getPassphraseHashAlgorithm().equals(loadedDID.getPassphraseHashAlgorithm())) {
            r.errorCode = AuthenticateDIDRequest.DID_PASSPHRASE_HASH_ALGORITHM_MISMATCH;
            r.did.setAuthenticated(false);
            return;
        }
        String passphraseHash = loadedDID.getPassphraseHash();
        Boolean authN = HashUtil.verifyHash(r.did.getPassphrase(), passphraseHash);
        LOG.info("AuthN: "+(authN != null && authN));
        r.did.setAuthenticated(authN != null && authN);
        if(r.did.getAuthenticated()) {
            r.did = loadedDID;
            r.did.setAuthenticated(true);
        }
    }

    private void authenticateOrCreate(AuthenticateDIDRequest r) {
        r.did = verify(r.did);
        if(!r.did.getVerified()) {
            save(r.did);
        } else {
            authenticate(r);
        }
    }

    private boolean isNew(DID didToLoad) {
        LoadDIDDAO dao = new LoadDIDDAO(infoVaultDB, didToLoad);
        dao.execute();
        DID loadedDID = dao.getLoadedDID();
        return loadedDID == null || loadedDID.getUsername() == null || loadedDID.getUsername().isEmpty();
    }

    @Override
    public boolean start(Properties properties) {
        super.start(properties);
        LOG.info("Starting....");
        updateStatus(ServiceStatus.STARTING);

        updateStatus(ServiceStatus.RUNNING);
        LOG.info("Started.");
        return true;
    }

    @Override
    public boolean shutdown() {
        super.shutdown();
        LOG.info("Shutting down....");
        updateStatus(ServiceStatus.SHUTTING_DOWN);

        updateStatus(ServiceStatus.SHUTDOWN);
        LOG.info("Shutdown.");
        return true;
    }

    @Override
    public boolean gracefulShutdown() {
        return shutdown();
    }

//    public static void main(String[] args) {
//        DIDService service = new DIDService();
//        DID did = new DID();
//        did.setAlias("Alice");
//        did.setPassphrase("1234");
//        service.create(did);
//    }

}
