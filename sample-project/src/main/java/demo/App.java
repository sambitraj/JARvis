package demo;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class App {
    private static final Logger LOG = LogManager.getLogger(App.class);
    private static final ObjectMapper MAPPER = new ObjectMapper();

    public static String toJson(Object o) throws Exception {
        LOG.info("Serializing {}", o);
        return MAPPER.writeValueAsString(o);
    }
}
