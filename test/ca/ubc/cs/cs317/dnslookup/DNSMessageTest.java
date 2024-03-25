package ca.ubc.cs.cs317.dnslookup;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

public class DNSMessageTest {
    @Test
    public void testConstructor() {
        DNSMessage message = new DNSMessage((short)23);
        assertFalse(message.getQR());
        assertFalse(message.getRD());
        assertEquals(0, message.getQDCount());
        assertEquals(0, message.getANCount());
        assertEquals(0, message.getNSCount());
        assertEquals(0, message.getARCount());
        assertEquals(23, message.getID());
    }
    @Test
    public void testBasicFieldAccess() {
        DNSMessage message = new DNSMessage((short)23);
        message.setID(55);

        message.setTC(true);
        assertTrue(message.getTC());
        message.setTC(false);
        assertFalse(message.getTC());
        message.setAA(true);
        assertTrue(message.getAA());
        message.setAA(false);
        assertFalse(message.getAA());
        message.setQR(true);
        assertTrue(message.getQR());
        message.setQR(false);
        assertFalse(message.getQR());
        message.setRD(true);
        assertTrue(message.getRD());
        message.setRD(false);
        assertFalse(message.getRD());
        message.setRA(true);
        assertTrue(message.getRA());
        message.setRA(false);
        assertFalse(message.getRA());

        message.setRcode(7);
        message.setQDCount(5);

        message.setQR(true);
        message.setAA(true);
        message.setTC(true);
        message.setRD(true);
        message.setOpcode(2);

        assertEquals(2, message.getOpcode());

        assertEquals(55, message.getID());
        assertEquals(7, message.getRcode());
        assertEquals(5, message.getQDCount());


    }
    @Test
    public void testAddQuestion() {
        DNSMessage request = new DNSMessage((short)23);
        DNSQuestion question = new DNSQuestion("norm.cs.ubc.ca", RecordType.A, RecordClass.IN);
        request.addQuestion(question);
        byte[] content = request.getUsed();

        //System.out.println(content);

        DNSMessage reply = new DNSMessage(content, content.length);

        System.out.println(request);
        System.out.println(reply);

        assertEquals(request.getID(), reply.getID());
        assertEquals(request.getQDCount(), reply.getQDCount());
        assertEquals(request.getANCount(), reply.getANCount());
        assertEquals(request.getNSCount(), reply.getNSCount());
        assertEquals(request.getARCount(), reply.getARCount());
        DNSQuestion replyQuestion = reply.getQuestion();
        assertEquals(question, replyQuestion);
    }
    @Test
    public void testAddResourceRecord() {
        DNSMessage request = new DNSMessage((short)23);
        DNSQuestion question = new DNSQuestion("norm.cs.ubc.ca", RecordType.NS, RecordClass.IN);
        ResourceRecord rr = new ResourceRecord(question, RecordType.NS.getCode(), "ns1.cs.ubc.ca");
        request.addResourceRecord(rr);
        byte[] content = request.getUsed();

        DNSMessage reply = new DNSMessage(content, content.length);
        assertEquals(request.getID(), reply.getID());
        assertEquals(request.getQDCount(), reply.getQDCount());
        assertEquals(request.getANCount(), reply.getANCount());
        assertEquals(request.getNSCount(), reply.getNSCount());
        assertEquals(request.getARCount(), reply.getARCount());
        ResourceRecord replyRR = reply.getRR();
        assertEquals(rr, replyRR);
    }
}
