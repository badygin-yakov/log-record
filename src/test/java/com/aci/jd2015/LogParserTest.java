package com.aci.jd2015;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.text.ParseException;

import org.apache.commons.lang3.StringUtils;
import org.junit.Test;

public class LogParserTest {
  public static void startProcessCheck(LogParser parser, String inFileName, String checkFileName)
      throws IOException {
    File tmpFile = File.createTempFile("jd2015", ".log");
    try {
      try (InputStream is = LogParserTest.class.getResourceAsStream(inFileName);
          OutputStream os = new FileOutputStream(tmpFile)) {
        parser.process(is, os);
      }
      try (
          BufferedReader readerCheck = new BufferedReader(
              new InputStreamReader(LogParserTest.class.getResourceAsStream(checkFileName), "UTF-8"));
          BufferedReader readerResult = new BufferedReader(
              new InputStreamReader(new FileInputStream(tmpFile.getPath()), "UTF-8"))) {
        String check;
        String result;

        int lineNo = 0;
        while (true) {
          check = readerCheck.readLine();
          result = readerResult.readLine();
          if (null == check && null == result) {
            break;
          }
          lineNo++;
          if (!StringUtils.equals(check, result)) {
            throw new RuntimeException("Error on the line #" + lineNo);
          }
        }
      }
    } finally {
      tmpFile.delete();
    }
  }

  @Test
  public void testExample1Process() throws Exception {
    startProcessCheck(new LogParserImpl(), "testExample1.log", "testExample1_answer.log");
  }

  @Test
  public void testExample2Process() throws Exception {
    startProcessCheck(new LogParserImpl(), "testExample2.log", "testExample2_answer.log");
  }

  @Test
  public void testExample3Process() throws Exception{
    startProcessCheck(new LogParserImpl(), "testExample3.log", "testExample3_answer.log");
  }

  @Test(expected = IOException.class)
  public void testExample4InvalidInput() throws Exception{
    startProcessCheck(new LogParserImpl(), "testExample4.log", "testExample4_answer.log");
  }

  @Test(expected = IOException.class)
  public void testExample5InvalidFormatDate() throws Exception{
    startProcessCheck(new LogParserImpl(), "testExample5.log", "testExample5_answer.log");
  }
}
