package org.t246osslab.easybuggy4sb.vulnerabilities;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;

import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.not;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Tests for CodeInjectionController to verify that:
 * 1. The ScriptEngine.eval() code injection sink has been eliminated.
 * 2. Valid JSON is accepted and the success message is shown.
 * 3. Invalid JSON is rejected gracefully without executing injected code.
 * 4. Classic code injection payloads are blocked (no arbitrary code execution).
 */
@RunWith(SpringRunner.class)
@SpringBootTest
@AutoConfigureMockMvc
public class CodeInjectionControllerTest {

    @Autowired
    private MockMvc mockMvc;

    // --- Positive cases: valid JSON should be accepted ---

    /**
     * A simple JSON object is valid and should return the "Valid JSON" message.
     */
    @Test
    @WithMockUser
    public void testValidJsonObject_returnsValidMessage() throws Exception {
        mockMvc.perform(get("/eb/v1/codeijc")
                .param("jsonString", "{\"key\":\"value\"}")
                .accept(MediaType.TEXT_HTML))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("Valid JSON")));
    }

    /**
     * A JSON array is valid and should return the "Valid JSON" message.
     */
    @Test
    @WithMockUser
    public void testValidJsonArray_returnsValidMessage() throws Exception {
        mockMvc.perform(get("/eb/v1/codeijc")
                .param("jsonString", "[1,2,3]")
                .accept(MediaType.TEXT_HTML))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("Valid JSON")));
    }

    /**
     * A JSON string literal is valid and should return the "Valid JSON" message.
     */
    @Test
    @WithMockUser
    public void testValidJsonString_returnsValidMessage() throws Exception {
        mockMvc.perform(get("/eb/v1/codeijc")
                .param("jsonString", "\"hello\"")
                .accept(MediaType.TEXT_HTML))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("Valid JSON")));
    }

    /**
     * A nested JSON object is valid and should return the "Valid JSON" message.
     */
    @Test
    @WithMockUser
    public void testValidNestedJson_returnsValidMessage() throws Exception {
        mockMvc.perform(get("/eb/v1/codeijc")
                .param("jsonString", "{\"a\":{\"b\":1},\"c\":[true,false,null]}")
                .accept(MediaType.TEXT_HTML))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("Valid JSON")));
    }

    // --- Negative cases: invalid JSON should be rejected gracefully ---

    /**
     * Plain text (not valid JSON) should be rejected and return an error message.
     */
    @Test
    @WithMockUser
    public void testPlainText_returnsInvalidMessage() throws Exception {
        mockMvc.perform(get("/eb/v1/codeijc")
                .param("jsonString", "not valid json")
                .accept(MediaType.TEXT_HTML))
                .andExpect(status().isOk())
                .andExpect(content().string(not(containsString("Valid JSON"))));
    }

    /**
     * Malformed JSON (missing closing brace) should be rejected.
     */
    @Test
    @WithMockUser
    public void testMalformedJson_returnsInvalidMessage() throws Exception {
        mockMvc.perform(get("/eb/v1/codeijc")
                .param("jsonString", "{\"key\": \"value\"")
                .accept(MediaType.TEXT_HTML))
                .andExpect(status().isOk())
                .andExpect(content().string(not(containsString("Valid JSON"))));
    }

    // --- Security cases: code injection payloads must NOT be executed ---

    /**
     * The classic code injection payload ({}');java.lang.System.exit(0);//) must
     * NOT cause the JVM to terminate or return a "Valid JSON" success response.
     * With the old ScriptEngine.eval() implementation this payload would call
     * System.exit(0). With the Jackson-based fix it is simply invalid JSON.
     */
    @Test
    @WithMockUser
    public void testClassicCodeInjectionPayload_isRejectedAsInvalidJson() throws Exception {
        // This is the documented exploit noted in messages.properties:
        // msg.note.codeinjection = If you enter {}');java.lang.System.exit(0);// ...
        String injectionPayload = "{}');java.lang.System.exit(0);//";
        mockMvc.perform(get("/eb/v1/codeijc")
                .param("jsonString", injectionPayload)
                .accept(MediaType.TEXT_HTML))
                .andExpect(status().isOk())
                .andExpect(content().string(not(containsString("Valid JSON"))));
    }

    /**
     * A payload embedding a JavaScript alert (XSS-style injection into eval context)
     * should not result in a "Valid JSON" success and must not execute.
     */
    @Test
    @WithMockUser
    public void testJavaScriptInjectionPayload_isRejectedAsInvalidJson() throws Exception {
        String injectionPayload = "{}'); alert('xss'); //";
        mockMvc.perform(get("/eb/v1/codeijc")
                .param("jsonString", injectionPayload)
                .accept(MediaType.TEXT_HTML))
                .andExpect(status().isOk())
                .andExpect(content().string(not(containsString("Valid JSON"))));
    }

    /**
     * A payload using single-quote escape to break out of the JSON.parse() context
     * — as was possible with the old eval-based implementation — must be rejected.
     */
    @Test
    @WithMockUser
    public void testSingleQuoteBreakoutPayload_isRejectedAsInvalidJson() throws Exception {
        String injectionPayload = "' + java.lang.Runtime.getRuntime().exec('id') + '";
        mockMvc.perform(get("/eb/v1/codeijc")
                .param("jsonString", injectionPayload)
                .accept(MediaType.TEXT_HTML))
                .andExpect(status().isOk())
                .andExpect(content().string(not(containsString("Valid JSON"))));
    }

    /**
     * A newline-based bypass attempt (to split the injected script across lines)
     * should be rejected because Jackson validates JSON structure, not JavaScript.
     */
    @Test
    @WithMockUser
    public void testNewlineInjectionPayload_isRejectedAsInvalidJson() throws Exception {
        // Encoded as escape sequences: \r\n between statements
        String injectionPayload = "{}\r\njava.lang.System.exit(0);";
        mockMvc.perform(get("/eb/v1/codeijc")
                .param("jsonString", injectionPayload)
                .accept(MediaType.TEXT_HTML))
                .andExpect(status().isOk())
                .andExpect(content().string(not(containsString("Valid JSON"))));
    }

    // --- Boundary cases ---

    /**
     * An empty/blank JSON string should prompt the user to enter a JSON string
     * (not crash and not show "Valid JSON").
     */
    @Test
    @WithMockUser
    public void testBlankInput_returnsEnterJsonPrompt() throws Exception {
        mockMvc.perform(get("/eb/v1/codeijc")
                .accept(MediaType.TEXT_HTML))
                .andExpect(status().isOk())
                .andExpect(content().string(not(containsString("Valid JSON"))));
    }

    /**
     * A JSON null literal is valid JSON and should return the "Valid JSON" message.
     */
    @Test
    @WithMockUser
    public void testJsonNullLiteral_returnsValidMessage() throws Exception {
        mockMvc.perform(get("/eb/v1/codeijc")
                .param("jsonString", "null")
                .accept(MediaType.TEXT_HTML))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("Valid JSON")));
    }
}
