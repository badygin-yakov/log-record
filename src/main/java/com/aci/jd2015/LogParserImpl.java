package com.aci.jd2015;


import java.io.*;
import java.security.MessageDigest;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;


public class LogParserImpl implements LogParser {
    private static final String ALGORITHM = "MD5";
    private static final String CONTROLSUMPREFIX = "CRC_";
    private static final String DATEFORMAT = "dd.MM.yyyy HH:mm:ss.SSS";
    private static final long TIMEDELTA = 10000;


    private List<String> allLineInFile;
    private List<String> body;
    private List<String> headers;
    private List<Message> result;

    public LogParserImpl(){
        allLineInFile = new ArrayList<>();
        result = new ArrayList<>();
    }

    @Override
    public void process(InputStream is, OutputStream os) throws IOException {
        try (
                BufferedReader br = new BufferedReader(new InputStreamReader(is));
                BufferedWriter bw = new BufferedWriter(new OutputStreamWriter(os));
        ){
            String line;
            while ((line = br.readLine()) != null) {
                if (checkFormat(line)) {
                    allLineInFile.add(trimString(line));
                    if (line.startsWith(CONTROLSUMPREFIX)){
                        Message m  = getMessage();
                        if (m == null){
                            throw new IOException("Invalid input");
                        }
                        if ((!result.isEmpty()) && (result.get(result.size() - 1).getDate().getTime() + TIMEDELTA < m.getDate().getTime())){
                            writeToFile(bw);
                        }
                        result.add(m);
                    }
                } else {
                    throw new InputMismatchException("Bad format: " + line);
                }
            }
            if (!result.isEmpty()){
                writeToFile(bw);
            }
        }
    }

    /**
     *
     * Count check sum for line
     *
     * @param input line for which you want to count check sum
     *
     * */
    private String getControlSum(String input){
        try {
            final MessageDigest md = MessageDigest.getInstance(ALGORITHM);
            byte[] dataBytes = input.getBytes();
            md.update(dataBytes);
            byte[] mdBytes = md.digest();

            StringBuilder sb = new StringBuilder();
            for (byte mdByte : mdBytes) {
                sb.append(Integer.toString((mdByte & 0xff) + 0x100, 16)
                        .substring(1));
            }
            return sb.toString();
        } catch (Exception e){
            e.printStackTrace();
        }
        return "";
    }

    /**
     *
     * @param input line for which check format
     * @return boolean
     */

    private boolean checkFormat(String input){
        Pattern headersCheck = Pattern.compile("^(0[1-9]|[12][0-9]|3[01])[.](0[1-9]|1[012])[.](19|20)\\d\\d\\s([0-1]\\d|2[0-3])(:[0-5]\\d){2}[.]\\d\\d\\d\\s.{0,1024}$");
        Pattern stringsCheck = Pattern.compile("^(?!"+ CONTROLSUMPREFIX +").{0,1024}");
        Pattern controlSumCheck = Pattern.compile("^"+ CONTROLSUMPREFIX +"[a-z0-9]{32}$");
        Matcher headersMatcher = headersCheck.matcher(input);
        Matcher stringsMatcher = stringsCheck.matcher(input);
        Matcher controlSumMatcher = controlSumCheck.matcher(input);

        return headersMatcher.matches() || stringsMatcher.matches() || controlSumMatcher.matches();
    }

    private String trimString (String str) {
        return str.replaceAll("[\n\r]", "");
    }

    private void writeToFile(BufferedWriter pw) throws IOException{
        Collections.sort(result);
        for (Message m :
                result) {
            pw.write(m.toString());
        }
        result = new ArrayList<>();
    }

    private int getControlSumIndex(){
        for (int i = 0; i < allLineInFile.size(); i++) {
            if(allLineInFile.get(i).startsWith(CONTROLSUMPREFIX)) {
                return i;
            }
        }
        return -1;
    }

    private Message getMessage(){
        this.headers = new ArrayList<>();
        this.body = new ArrayList<>();

        int controlSumIndex = getControlSumIndex();
        parseMessage(subList(controlSumIndex));
        String fullControlSum = allLineInFile.get(controlSumIndex);
        String controlSum = fullControlSum.substring(CONTROLSUMPREFIX.length());

        for (int i = 0; i < headers.size(); i++) {
            String currentHeader = headers.get(i);
            if (getControlSum(currentHeader).equals(controlSum)) {
                return assembleMessage(i, controlSumIndex);
            }

            int n = Long.SIZE - body.size();
            long searchMax = -1L >>> n;
            long search = 1L;
            while (search <= searchMax) {
                StringBuilder toCheck = new StringBuilder(currentHeader);
                long bin = search;
                int k = 0;
                while (bin != 0) {
                    if ((bin & 1) == 1) {
                        toCheck.append(body.get(k));
                    }
                    bin >>= 1;
                    k++;
                }
                if (getControlSum(toCheck.toString()).equals(controlSum)) {
                    return assembleMessage(i, controlSumIndex, search);
                }
                search++;
            }
        }
        return null;
    }

    private void parseMessage(List<String> listMessage){
        // Pattern for dd.MM.yyyy HH:mm:ss.SSS <msg str1>
        Pattern p = Pattern.compile("^(0[1-9]|[12][0-9]|3[01])[.](0[1-9]|1[012])[.](19|20)\\d\\d\\s([0-1]\\d|2[0-3])(:[0-5]\\d){2}[.]\\d\\d\\d.*");
        Matcher m;
        for (String str : listMessage) {
            m = p.matcher(str);
            if (m.matches()) {
                headers.add(str);
            } else {
                body.add(str);
            }
        }
    }

    private Message assembleMessage(int headerIndex, int controlSumIndex, long bin){

        Date messageDate = null;
        int length = Long.bitCount(bin) + 2;
        String[] messageArray = new String[length];
        messageArray[0] = headers.get(headerIndex);
        messageArray[length - 1] = allLineInFile.get(controlSumIndex);

        int i = 1;
        int j = 0;
        while (bin != 0) {
            if ((bin & 1) == 1) {
                messageArray[i] = body.get(j);
                i++;
            }
            bin >>= 1;
            j++;
        }

        try {
            messageDate = parseDate(messageArray[0].substring(0, DATEFORMAT.length()));
        } catch (ParseException e) {
            e.printStackTrace();
        }

        removeCompleteMessage(messageArray);
        return new Message(messageDate, messageArray);
    }

    private Message assembleMessage(int headerIndex, int controlSumIndex){

        Date messageDate = null;

        // Message consists of header & control sum
        String[] message = new String[2];
        message[0] = headers.get(headerIndex);
        message[1] = allLineInFile.get(controlSumIndex);

        try {
            messageDate = parseDate(message[0].substring(0, DATEFORMAT.length()));
        } catch (ParseException e) {
            e.printStackTrace();
        }

        removeCompleteMessage(message);

        return new Message(messageDate, message);
    }

    private Date parseDate(String dateString) throws ParseException {
        SimpleDateFormat sdf = new SimpleDateFormat(DATEFORMAT);
        return sdf.parse(dateString);
    }

    private void removeCompleteMessage (String[] completeMessage) {
        for (String aCompleteMessage : completeMessage) {
            allLineInFile.remove(aCompleteMessage);
        }
    }

    private List<String> subList(int toIndex){
        return allLineInFile.subList(0, toIndex);
    }

    private final class Message implements Comparable<Message> {

        private Date date;
        private String[] body;

        private Message(Date date, String[] message) {
            this.date = date;
            body = message;
        }

        private Date getDate() {
            return date;
        }

        @Override
        public int compareTo(Message message) {
            return date.compareTo(message.getDate());
        }

        @Override
        public String toString() {
            StringBuilder sb = new StringBuilder();
            for(String str : body) {
                sb.append(str);
                sb.append("\r\n");
            }
            return sb.toString();
        }
    }
}
