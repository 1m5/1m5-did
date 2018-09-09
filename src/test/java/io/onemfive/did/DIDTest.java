package io.onemfive.did;

import io.onemfive.core.OneMFiveAppContext;
import io.onemfive.core.client.Client;
import io.onemfive.core.client.ClientAppManager;
import io.onemfive.data.*;
import io.onemfive.data.util.ByteArrayWrapper;
import io.onemfive.data.util.DLC;
import org.junit.AfterClass;
import org.junit.BeforeClass;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

/**
 * TODO: Add Description
 *
 * @author objectorange
 */
public class DIDTest {

    private static CountDownLatch lock;

    @BeforeClass
    public static void startUp() {

    }

    public void testAuthn() {

    }

    @AfterClass
    public static void tearDown() {
//        try {
//            lock.await(5, TimeUnit.SECONDS);
//        } catch (InterruptedException e) {}
//
    }

}
