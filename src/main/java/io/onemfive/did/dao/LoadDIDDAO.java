package io.onemfive.did.dao;

import io.onemfive.core.infovault.InfoVaultDB;
import io.onemfive.core.infovault.LocalFSDAO;
import io.onemfive.data.DID;
import io.onemfive.data.util.JSONParser;

import java.io.FileNotFoundException;
import java.util.Map;
import java.util.logging.Logger;

public class LoadDIDDAO extends LocalFSDAO {

    private Logger LOG = Logger.getLogger(LoadDIDDAO.class.getName());

    private DID providedDID;
    private DID loadedDID = new DID();

    public LoadDIDDAO(InfoVaultDB infoVaultDB, DID did) {
        super(infoVaultDB);
        this.providedDID = did;
    }

    @Override
    public void execute() {
        byte[] content;
        try {
            content = infoVaultDB.load(DID.class.getName(), providedDID.getUsername());
        } catch (FileNotFoundException e) {
            exception = e;
            return;
        }
        String jsonBody = new String(content);
        LOG.info("JSON loaded: "+jsonBody);
        loadedDID.fromMap((Map<String,Object>)JSONParser.parse(jsonBody));
    }

    public DID getLoadedDID() {
        return loadedDID;
    }
}
