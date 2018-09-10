package io.onemfive.did;

import org.junit.AfterClass;
import org.junit.BeforeClass;

import java.util.concurrent.CountDownLatch;

/**
 * TODO: Add Description
 *
 * @author objectorange
 */
public class DIDTest {

    private static CountDownLatch lock;
    private static DIDService service;

    @BeforeClass
    public static void startUp() {
//        service = new DIDService(null,null);
//        service.start(null);
    }

    public void testCreate() {

    }

    @AfterClass
    public static void tearDown() {
//        try {
//            lock.await(5, TimeUnit.SECONDS);
//        } catch (InterruptedException e) {}
//
    }

}
