package io.onemfive.did;

import io.onemfive.data.Hash;
import io.onemfive.data.util.HashUtil;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

/**
 * TODO: Add Description
 *
 * @author objectorange
 */
public class DIDTest {

    @Before
    public void startUp() {

    }

    @Test
    public void testAuthn() {
        String alias = "Alice";
        String passphrase = "1234";
        boolean aliasVerified = false;
        boolean passphraseVerified = false;
        try {
            Hash aliasHash = HashUtil.generateHash(alias, Hash.Algorithm.SHA1);
            aliasVerified = HashUtil.verifyHash(alias, aliasHash);
            Hash passphraseHash = HashUtil.generatePasswordHash(passphrase);
            passphraseVerified = HashUtil.verifyPasswordHash(passphrase, passphraseHash);
        } catch(Exception e) {
            System.out.println(e.getLocalizedMessage());
        }
        assert (aliasVerified);
        assert (passphraseVerified);
    }

    @After
    public void tearDown() {

    }

}
