package demo;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.assertEquals;

class AppTest {
    @Test
    void serializes() throws Exception {
        assertEquals("\"hi\"", App.toJson("hi"));
    }
}
