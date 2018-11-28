package io.onemfive.did;

import io.onemfive.core.*;
import io.onemfive.did.dao.LoadDIDDAO;
import io.onemfive.did.dao.SaveDIDDAO;
import io.onemfive.core.util.HashUtil;
import io.onemfive.data.DID;
import io.onemfive.data.Envelope;
import io.onemfive.data.Route;
import io.onemfive.data.util.DLC;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.*;
import java.util.logging.Logger;
import java.util.regex.Pattern;

/**
 * Decentralized IDentifier (DID) Service
 *
 * @author objectorange
 */
public class DIDService extends BaseService {

    private static final Logger LOG = Logger.getLogger(DIDService.class.getName());

    public static final String OPERATION_VERIFY = "VERIFY";
    public static final String OPERATION_AUTHENTICATE = "AUTHENTICATE";
    public static final String OPERATION_CREATE = "CREATE";
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
                if(r.did.getAlias() == null) {
                    r.errorCode = GetLocalDIDRequest.DID_ALIAS_REQUIRED;
                    break;
                }
                try {
                    r.did = getLocalDID(r);
                } catch (NoSuchAlgorithmException e1) {
                    r.errorCode = GetLocalDIDRequest.DID_PASSPHRASE_HASH_ALGORITHM_UNKNOWN;
                    break;
                } catch (InvalidKeySpecException e1) {
                    r.errorCode = GetLocalDIDRequest.DID_PASSPHRASE_HASH_ALGORITHM_UNKNOWN;
                    LOG.warning(e1.getLocalizedMessage());
                    break;
                }
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
                if(r.did.getAlias() == null) {
                    r.errorCode = AuthenticateDIDRequest.DID_ALIAS_REQUIRED;
                    break;
                }
                if(r.did.getPassphrase() == null) {
                    r.errorCode = AuthenticateDIDRequest.DID_PASSPHRASE_REQUIRED;
                    break;
                }
                try {
                    authenticate(r);
                } catch (NoSuchAlgorithmException e1) {
                    r.errorCode = AuthenticateDIDRequest.DID_PASSPHRASE_HASH_ALGORITHM_UNKNOWN;
                } catch (InvalidKeySpecException e1) {
                    r.errorCode = AuthenticateDIDRequest.DID_PASSPHRASE_HASH_ALGORITHM_UNKNOWN;
                    LOG.warning(e1.getLocalizedMessage());
                }
                if(r.did.getAuthenticated()) {
                    e.setDID(r.did);
                }
                break;
            }
            case OPERATION_CREATE: {
                DID did = (DID)DLC.getData(DID.class,e);
                try {
                    e.setDID(create(did));
                } catch (NoSuchAlgorithmException e1) {
                    LOG.warning(e1.getLocalizedMessage());
                } catch (InvalidKeySpecException e1) {
                    LOG.warning(e1.getLocalizedMessage());
                }
                break;
            }
            case OPERATION_AUTHENTICATE_CREATE: {
                AuthenticateDIDRequest r = (AuthenticateDIDRequest)DLC.getData(AuthenticateDIDRequest.class,e);
                try {
                    authenticateOrCreate(r);
                } catch (NoSuchAlgorithmException e1) {
                    r.errorCode = AuthenticateDIDRequest.DID_PASSPHRASE_HASH_ALGORITHM_UNKNOWN;
                } catch (InvalidKeySpecException e1) {
                    r.errorCode = AuthenticateDIDRequest.DID_PASSPHRASE_HASH_ALGORITHM_UNKNOWN;
                    LOG.warning(e1.getLocalizedMessage());
                }
                break;
            }
            case OPERATION_REVOKE: {

                break;
            }
            case OPERATION_HASH: {
                HashRequest r = (HashRequest)DLC.getData(HashRequest.class,e);
                r.hash = HashUtil.generateHash(r.contentToHash);
                break;
            }
            case OPERATION_VERIFY_HASH:{
                VerifyHashRequest r = (VerifyHashRequest)DLC.getData(VerifyHashRequest.class,e);
                Boolean isMath = HashUtil.verifyHash(r.content, r.hashToVerify);
                if(isMath != null)
                    r.isAMatch = isMath;
                break;
            }
            default: deadLetter(e); // Operation not supported
        }
    }

    private DID getLocalDID(io.onemfive.did.GetLocalDIDRequest r) throws NoSuchAlgorithmException, InvalidKeySpecException {
        if(localUserDIDs.containsKey(r.did.getAlias()))
            return localUserDIDs.get(r.did.getAlias());
        if(r.did.getPassphrase() == null) {
            r.errorCode = io.onemfive.did.GetLocalDIDRequest.DID_PASSPHRASE_REQUIRED;
            return r.did;
        }
        if(r.did.getPassphraseHashAlgorithm() == null) {
            r.errorCode = io.onemfive.did.GetLocalDIDRequest.DID_PASSPHRASE_HASH_ALGORITHM_UNKNOWN;
            return r.did;
        }
        return create(r.did);
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
        if(didLoaded != null && did.getAlias() != null && did.getAlias().equals(didLoaded.getAlias())) {
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
     * Creates and returns identity key using master key for provided alias if one does not exist.
     * If master key is not present, one will be created by the Key Ring Service.
     * @param did DID
     */
    private DID create(DID did) throws NoSuchAlgorithmException, InvalidKeySpecException {
        LOG.info("Received create DID request.");
        did.setPassphraseHash(HashUtil.generateHash(did.getPassphrase()));
        did.setAuthenticated(true);
        did.setVerified(true);
        did.setStatus(DID.Status.ACTIVE);
        SaveDIDDAO dao = new SaveDIDDAO(infoVaultDB, did, true);
        dao.execute();
        if(dao.getException() != null) {
            LOG.warning("Create DID threw exception: "+dao.getException().getLocalizedMessage());
        }
        return did;
    }

    /**
     * Authenticates passphrase
     * @param r AuthenticateDIDRequest
     */
    private void authenticate(AuthenticateDIDRequest r) throws NoSuchAlgorithmException, InvalidKeySpecException {
        LoadDIDDAO dao = new LoadDIDDAO(infoVaultDB, r.did);
        dao.execute();
        DID loadedDID = dao.getLoadedDID();
        if(loadedDID == null || loadedDID.getAlias() == null || loadedDID.getAlias().isEmpty()) {
            r.errorCode = AuthenticateDIDRequest.DID_ALIAS_UNKNOWN;
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

    private void authenticateOrCreate(AuthenticateDIDRequest r) throws NoSuchAlgorithmException, InvalidKeySpecException {
        r.did = verify(r.did);
        if(!r.did.getVerified()) {
            create(r.did);
        } else {
            authenticate(r);
        }
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

}
