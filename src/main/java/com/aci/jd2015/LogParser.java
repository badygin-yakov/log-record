package com.aci.jd2015;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

public interface LogParser {
  void process(InputStream is, OutputStream os) throws IOException;
}
