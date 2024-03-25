package ca.ubc.cs.cs317.dnslookup;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.IntStream;

public class DNSMessage {
    public static final int MAX_DNS_MESSAGE_LENGTH = 512;
    private final Map<String, Integer> nameToPosition = new HashMap<>();
    private final Map<Integer, String> positionToName = new HashMap<>();
    private final ByteBuffer buffer;


    /**
     * Initializes an empty DNSMessage with the given id.
     *
     * @param id The id of the message.
     */
    public DNSMessage(short id) {
        this.buffer = ByteBuffer.allocate(MAX_DNS_MESSAGE_LENGTH);
        this.buffer.putShort(0,(short) id);
        this.buffer.position(12);
    }

    /**
     * Initializes a DNSMessage with the first length bytes of the given byte array.
     *
     * @param recvd The byte array containing the received message
     * @param length The length of the data in the array
     */
    public DNSMessage(byte[] recvd, int length) {
        this.buffer = ByteBuffer.wrap(recvd, 0, length);
        this.buffer.position(12);
    }

    /**
     * Getters and setters for the various fixed size and fixed location fields of a DNSMessage
     *
     */
    public int getID() {
        int result = this.buffer.getShort(0);
        result = (result & 0xFFFF);
        return(result);
    }

    public void setID(int id) {
        this.buffer.putShort(0, (short) id);
    }

    public boolean getQR() {
        if((this.buffer.get(2) >> 7 & 1) == 1 ){
            return true;
        }
        else return false;
    }

    public void setQR(boolean qr) {
        if(qr){
            this.buffer.put(2, (byte) (this.buffer.get(2) |  0x80) );
        }
        else{
            this.buffer.put(2, (byte) (this.buffer.get(2) &  0x7F) );
        }
    }

    public boolean getAA() {
        if((this.buffer.get(2) >> 2 & 1) == 1 ){
            return true;
        }
        else return false;
    }

    public void setAA(boolean aa) {
        if(aa){
            this.buffer.put(2, (byte) (this.buffer.get(2) |  0x4) );
        }
        else{
            this.buffer.put(2, (byte) (this.buffer.get(2) &  0xFB) );
        }
    }

    public int getOpcode() {
        return ((this.buffer.get(2) >> 3) & 0xF);
    }

    public void setOpcode(int opcode) {
        this.buffer.put(2, (byte) ((this.buffer.get(2) &  0x87) | (opcode << 3) ) ); //I had made a silly mistake here and it took the longest to figure out.
    }

    public boolean getTC() {
        if((this.buffer.get(2) >> 1 & 1) == 1 ){
            return true;
        }
        else return false;
    }

    public void setTC(boolean tc) {
        if(tc){
            this.buffer.put(2, (byte) (this.buffer.get(2) |  0x2) );
        }
        else{
            this.buffer.put(2, (byte) (this.buffer.get(2) &  0xFD) );
        }
    }

    public boolean getRD() {
        if((this.buffer.get(2) & 1) == 1 ){
            return true;
        }
        else return false;
    }

    public void setRD(boolean rd) {
        if(rd){
            this.buffer.put(2, (byte) (this.buffer.get(2) |  0x1) );
        }
        else{
            this.buffer.put(2, (byte) (this.buffer.get(2) &  0xFE) );
        }
    }

    public boolean getRA() {
        if((this.buffer.get(3) >> 7 & 1) == 1 ){
            return true;
        }
        else return false;
    }

    public void setRA(boolean ra) {
        if(ra){
            this.buffer.put(3, (byte) (this.buffer.get(3) |  0x80) );
        }
        else{
            this.buffer.put(3, (byte) (this.buffer.get(3) &  0x7F) );
        }
    }

    public int getRcode() {
        return (this.buffer.get(3) & 0xF);
    }

    public void setRcode(int rcode) {
        this.buffer.put(3, (byte) ((this.buffer.get(3) & 0xF0) | rcode) );
    }

    public int getQDCount() {
        return (this.buffer.getShort(4));
    }

    public void setQDCount(int count) {
        this.buffer.putShort(4, (short) count);
    }

    public int getANCount() {
        return (this.buffer.getShort(6));
    }

    public int getNSCount() {
        return (this.buffer.getShort(8));
    }

    public int getARCount() {
        return (this.buffer.getShort(10));
    }

    public void setARCount(int count) {
        this.buffer.putShort(10, (short) count);
    }

    /**
     * Return the name at the current position() of the buffer.  This method is provided for you,
     * but you should ensure that you understand what it does and how it does it.
     *
     * The trick is to keep track of all the positions in the message that contain names, since
     * they can be the target of a pointer.  We do this by storing the mapping of position to
     * name in the positionToName map.
     *
     * @return The decoded name
     */
    public String getName() {
        // Remember the starting position for updating the name cache
        int start = buffer.position();
        int len = buffer.get() & 0xff;
        if (len == 0) return "";
        if ((len & 0xc0) == 0xc0) {  // This is a pointer
            int pointer = ((len & 0x3f) << 8) | (buffer.get() & 0xff);
            String suffix = positionToName.get(pointer);
            assert suffix != null;
            positionToName.put(start, suffix);
            return suffix;
        }
        byte[] bytes = new byte[len];
        buffer.get(bytes, 0, len);
        String label = new String(bytes, StandardCharsets.UTF_8);
        String suffix = getName();
        String answer = suffix.isEmpty() ? label : label + "." + suffix;
        positionToName.put(start, answer);
        return answer;
    }

    /**
     * The standard toString method that displays everything in a message.
     * @return The string representation of the message
     */
    public String toString() {
        // Remember the current position of the buffer so we can put it back
        // Since toString() can be called by the debugger, we want to be careful to not change
        // the position in the buffer.  We remember what it was and put it back when we are done.
        int end = buffer.position();
        final int DataOffset = 12;
        try {
            StringBuilder sb = new StringBuilder();
            sb.append("ID: ").append(getID()).append(' ');
            sb.append("QR: ").append(getQR()).append(' ');
            sb.append("OP: ").append(getOpcode()).append(' ');
            sb.append("AA: ").append(getAA()).append('\n');
            sb.append("TC: ").append(getTC()).append(' ');
            sb.append("RD: ").append(getRD()).append(' ');
            sb.append("RA: ").append(getRA()).append(' ');
            sb.append("RCODE: ").append(getRcode()).append(' ')
                    .append(dnsErrorMessage(getRcode())).append('\n');
            sb.append("QDCount: ").append(getQDCount()).append(' ');
            sb.append("ANCount: ").append(getANCount()).append(' ');
            sb.append("NSCount: ").append(getNSCount()).append(' ');
            sb.append("ARCount: ").append(getARCount()).append('\n');
            buffer.position(DataOffset);
            showQuestions(getQDCount(), sb);
            //showRRs("Authoritative", getANCount(), sb);
            showRRs("Name servers", getNSCount(), sb);
            showRRs("Additional", getARCount(), sb);
            return sb.toString();
        } catch (Exception e) {
            e.printStackTrace();
            return "toString failed on DNSMessage";
        }
        finally {
            buffer.position(end);
        }
    }

    /**
     * Add the text representation of all the questions (there are nq of them) to the StringBuilder sb.
     *
     * @param nq Number of questions
     * @param sb Collects the string representations
     */
    private void showQuestions(int nq, StringBuilder sb) {
        sb.append("Question [").append(nq).append("]\n");
        for (int i = 0; i < nq; i++) {
            DNSQuestion question = getQuestion();
            sb.append('[').append(i).append(']').append(' ').append(question).append('\n');
        }
    }

    /**
     * Add the text representation of all the resource records (there are nrrs of them) to the StringBuilder sb.
     *
     * @param kind Label used to kind of resource record (which section are we looking at)
     * @param nrrs Number of resource records
     * @param sb Collects the string representations
     */
    private void showRRs(String kind, int nrrs, StringBuilder sb) {
        sb.append(kind).append(" [").append(nrrs).append("]\n"); //Types the first line EG: Name Servers [13]
        for (int i = 0; i < nrrs; i++) {
            ResourceRecord rr = getRR();
            sb.append('[').append(i).append(']').append(' ').append(rr).append('\n');
        }
    }

    /**
     * Decode and return the question that appears next in the message.  The current position in the
     * buffer indicates where the question starts.
     *
     * @return The decoded question
     */
    public DNSQuestion getQuestion() {

        //Reading domain name
        //Didn't read helper functions and I had made this earlier. It works equivalently for simple ones, not for compressed ones.
//        int lenbyte = this.buffer.get();
//        StringBuilder domainname = new StringBuilder();
//        while(lenbyte != 0){
//            int remaininglength = lenbyte;
//            while(remaininglength != 0){
//                char convertedChar = (char) this.buffer.get();
//                domainname.append(convertedChar);
//                remaininglength = (remaininglength - 1);
//            }
//            lenbyte = this.buffer.get();
//            if(lenbyte != 0)
//                domainname.append(".");
//        }

        String domainname = getName();

        //Making Type object
        RecordType Rtype = RecordType.getByCode(this.buffer.getShort());

        //Making Class object
        RecordClass Ctype = RecordClass.getByCode(this.buffer.getShort());

        //Making DNSQuestion object
        DNSQuestion result = new DNSQuestion(domainname, Rtype, Ctype);

        return result;
    }

    /**
     * Decode and return the resource record that appears next in the message.  The current
     * position in the buffer indicates where the resource record starts.
     *
     * @return The decoded resource record
     */
    public ResourceRecord getRR() {

        String resourcename = getName(); // question.hostname
        RecordType type = RecordType.getByCode(this.buffer.getShort()); //question.type
        RecordClass cclass = RecordClass.getByCode(this.buffer.getShort());

        //Making DNSQuestion object
        DNSQuestion ques = new DNSQuestion(resourcename, type, cclass);

        if(ques.getRecordType() == RecordType.A){
            int ttl = this.buffer.getInt();
            short rdlen = this.buffer.getShort();

            int address = this.buffer.getInt();

            ByteBuffer buf = ByteBuffer.allocate(4);         //This was not working no matter what, I took help from here https://stackoverflow.com/questions/1936857/convert-integer-into-byte-array-java
            buf.putInt(address);
            byte[] addressinbytes = buf.array();
            InetAddress res = null;
            try {
                res = InetAddress.getByAddress(addressinbytes);
                ResourceRecord result = new ResourceRecord(ques,ttl, res);
                return result;

            } catch (UnknownHostException e) {
                System.out.println("ERROR");
                e.printStackTrace();
            }
            return null;
        }
        else if(ques.getRecordType() == RecordType.AAAA){
            int ttl = this.buffer.getInt();
            short rdlen = this.buffer.getShort();

            //I agree this is not a smart way to do it, but for some reason, but due to lack of time, this is what worked for me.
            //I'll make it better before PA2.2!
            int block1 = this.buffer.getInt();
            int block2 = this.buffer.getInt();
            int block3 = this.buffer.getInt();
            int block4 = this.buffer.getInt();
            ByteBuffer buf = ByteBuffer.allocate(16);         //This was not working no matter what, I took help from here https://stackoverflow.com/questions/1936857/convert-integer-into-byte-array-java
            buf.putInt(block1);
            buf.putInt(block2);
            buf.putInt(block3);
            buf.putInt(block4);

            byte[] addressinbytes = buf.array();

            InetAddress res = null;
            try {
                res = InetAddress.getByAddress(addressinbytes);
                ResourceRecord result = new ResourceRecord(ques,ttl, res);
                return result;

            } catch (UnknownHostException e) {
                System.out.println("ERROR");
                e.printStackTrace();
            }
            return null;
        }
        else if(ques.getRecordType() == RecordType.MX){
            int ttl = this.buffer.getInt();
            short rdlen = this.buffer.getShort();
            short pref = this.buffer.getShort();
            String Rdata = getName();
            ResourceRecord result = new ResourceRecord(ques,ttl, Rdata);
            return result;
        }
        else{
            int ttl = this.buffer.getInt();
            short rdlen = this.buffer.getShort();
            String Rdata = getName();
            ResourceRecord result = new ResourceRecord(ques,ttl, Rdata);
            return result;
        }
    }

    /**
     * Helper function that returns a hex string representation of a byte array. May be used to represent the result of
     * records that are returned by a server but are not supported by the application (e.g., SOA records).
     *
     * @param data a byte array containing the record data.
     * @return A string containing the hex value of every byte in the data.
     */
    private static String byteArrayToHexString(byte[] data) {
        return IntStream.range(0, data.length).mapToObj(i -> String.format("%02x", data[i])).reduce("", String::concat);
    }

    /**
     * Add an encoded name to the message. It is added at the current position and uses compression
     * as much as possible.  Compression is accomplished by remembering the position of every added
     * label.
     *
     * @param name The name to be added
     */
    public void addName(String name) {
        String label;
        while (name.length() > 0) {
            Integer offset = nameToPosition.get(name);
            if (offset != null) {
                int pointer = offset;
                pointer |= 0xc000;
                buffer.putShort((short)pointer);
                return;
            } else {
                nameToPosition.put(name, buffer.position());
                int dot = name.indexOf('.');
                label = (dot > 0) ? name.substring(0, dot) : name;
                buffer.put((byte)label.length());
                for (int j = 0; j < label.length(); j++) {
                    buffer.put((byte)label.charAt(j));
                }
                name = (dot > 0) ? name.substring(dot + 1) : "";
            }
        }
        buffer.put((byte)0);
    }

    /**
     * Add an encoded question to the message at the current position.
     * @param question The question to be added
     */
    public void addQuestion(DNSQuestion question) {

        setQDCount( (getQDCount()+1) ); // Incrementing QDCount by 1.


        //addName(byteArrayToHexString(question.getHostName().getBytes()));   // For the longest time, I was passing this to add name and couldn't figure out why.
                                                                                //Confusion arose because addName() says it adds an "encoded" name.

        addName(question.getHostName());

        this.buffer.putShort((short) question.getRecordType().getCode());
        this.buffer.putShort((short) question.getRecordClass().getCode());
    }

    /**
     * Add an encoded resource record to the message at the current position.
     * @param rr The resource record to be added
     */
    public void addResourceRecord(ResourceRecord rr) {

        setARCount((getARCount() + 1));

        if(rr.getRecordType() == RecordType.MX){

            addName(rr.getHostName());
            addQType(rr.getRecordType());
            addQClass(rr.getRecordClass());
            this.buffer.putInt((int) rr.getRemainingTTL());
            this.buffer.putShort((short) rr.getTextResult().length());
            this.buffer.putShort((short)0);
            addName(rr.getTextResult());
        }
        else if(rr.getRecordType() == RecordType.A){
            addName(rr.getHostName());
            addQType(rr.getRecordType());
            addQClass(rr.getRecordClass());
            this.buffer.putInt((int) rr.getRemainingTTL());
            this.buffer.putShort((short) 4);
            byte[] bytes = rr.getInetResult().getAddress();             //Disclosure, took this from https://stackoverflow.com/questions/2984601/how-to-get-a-byte-representation-from-a-ip-in-string-form-in-java
            this.buffer.put(bytes);
        }
        else if(rr.getRecordType() == RecordType.AAAA){
            addName(rr.getHostName());
            addQType(rr.getRecordType());
            addQClass(rr.getRecordClass());
            this.buffer.putInt((int) rr.getRemainingTTL());
            this.buffer.putShort((short) 16);
            byte[] bytes = rr.getInetResult().getAddress();             //Disclosure, took this from https://stackoverflow.com/questions/2984601/how-to-get-a-byte-representation-from-a-ip-in-string-form-in-java
            this.buffer.put(bytes);
        }
        else{
            addName(rr.getHostName());
            addQType(rr.getRecordType());
            addQClass(rr.getRecordClass());
            this.buffer.putInt((int) rr.getRemainingTTL());
            this.buffer.putShort((short) rr.getTextResult().length());
            addName(rr.getTextResult());
        }
    }

    /**
     * Add an encoded type to the message at the current position.
     * @param recordType The type to be added
     */
    private void addQType(RecordType recordType) {

        this.buffer.putShort((short) recordType.getCode());
    }

    /**
     * Add an encoded class to the message at the current position.
     * @param recordClass The class to be added
     */
    private void addQClass(RecordClass recordClass) {
        this.buffer.putShort((short) recordClass.getCode());
    }

    /**
     * Return a byte array that contains all the data comprising this message.  The length of the
     * array will be exactly the same as the current position in the buffer.
     * @return A byte array containing this message's data
     */
    public byte[] getUsed() {

        //Again, this is not the smartest way to do it, as I did more of the assignment, I understood that, but due to lack of time, I have left it as it is since it functions.
        int len = this.buffer.position();
        byte[] result = new byte[len];
        byte thisbyte;
        this.buffer.position(0);
        int i = 0;
        while(i < len){

            thisbyte = this.buffer.get();
            result[i] = thisbyte;
            i = i + 1;
        }
        return result;
    }

    /**
     * Returns a string representation of a DNS error code.
     *
     * @param error The error code received from the server.
     * @return A string representation of the error code.
     */
    public static String dnsErrorMessage(int error) {
        final String[] errors = new String[]{
                "No error", // 0
                "Format error", // 1
                "Server failure", // 2
                "Name error (name does not exist)", // 3
                "Not implemented (parameters not supported)", // 4
                "Refused" // 5
        };
        if (error >= 0 && error < errors.length)
            return errors[error];
        return "Invalid error message";
    }
}
