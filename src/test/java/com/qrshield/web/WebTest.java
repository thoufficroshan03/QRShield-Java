package com.qrshield.web;

import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.not;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.multipart;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrlPattern;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.qrshield.data.ScanRepository;
import com.qrshield.qr.QrTestImages;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

/** Integration tests: a temporary SQLite file is used, never the real instance/qrshield.db. */
@SuppressWarnings("null") // third-party MockMvc/Hamcrest/Spring Security Test @NonNull annotations absent in library sources
@SpringBootTest
@AutoConfigureMockMvc
class WebTest {
    private static final Path TMP;
    static {
        try { TMP = Files.createTempDirectory("qrshield-test"); }
        catch (IOException e) { throw new IllegalStateException(e); }
    }

    @DynamicPropertySource
    static void props(DynamicPropertyRegistry registry) {
        registry.add("spring.datasource.url", () -> "jdbc:sqlite:" + TMP.resolve("test.db"));
        registry.add("qrshield.tmp-dir", () -> TMP.resolve("uploads").toString());
        registry.add("qrshield.ti-provider", () -> "none");
    }

    @Autowired MockMvc mvc;
    @Autowired ScanRepository repository;

    @BeforeEach void clean() { repository.clear(); }

    private MvcResult scan(String url) throws Exception {
        return mvc.perform(post("/scan").with(csrf()).param("url", url).param("save_history", "on")).andReturn();
    }

    @Test void pagesLoad() throws Exception {
        for (String path : new String[]{"/", "/scan", "/qr-scanner", "/history", "/dashboard", "/about", "/health"}) {
            mvc.perform(get(path)).andExpect(status().isOk());
        }
        mvc.perform(get("/health")).andExpect(content().json("{\"status\":\"ok\"}"));
        mvc.perform(get("/")).andExpect(content().string(containsString("href=\"/qr-scanner\"")));
    }

    @Test void scanSavesRedirectsAndRedacts() throws Exception {
        MvcResult r = scan("http://1.2.3.4/login?token=SECRETVALUE");
        mvc.perform(post("/scan").with(csrf()).param("url", "http://1.2.3.4/login?token=SECRETVALUE").param("save_history", "on"))
           .andExpect(status().is3xxRedirection()).andExpect(redirectedUrlPattern("/result/*"));
        String location = r.getResponse().getRedirectedUrl();
        mvc.perform(get(location)).andExpect(status().isOk())
           .andExpect(content().string(containsString("IP address used as hostname")))
           .andExpect(content().string(containsString("token=[redacted]")))
           .andExpect(content().string(not(containsString("SECRETVALUE"))));
    }

    @Test void unsavedScanShowsResult() throws Exception {
        mvc.perform(post("/scan").with(csrf()).param("url", "https://example.com/"))
           .andExpect(status().isOk()).andExpect(content().string(containsString("Not saved")));
        mvc.perform(get("/history")).andExpect(content().string(containsString("No scans")));
    }

    @Test void invalidInputIs400() throws Exception {
        for (String bad : new String[]{"", "javascript:alert(1)", "http://"}) {
            mvc.perform(post("/scan").with(csrf()).param("url", bad)).andExpect(status().isBadRequest());
        }
    }

    @Test void htmlInputIsEscaped() throws Exception {
        mvc.perform(post("/scan").with(csrf()).param("url", "<script>alert(1)</script>"))
           .andExpect(status().isBadRequest())
           .andExpect(content().string(not(containsString("<script>alert(1)"))))
           .andExpect(content().string(containsString("&lt;script&gt;")));
    }

    @Test void sqlInjectionTextIsHarmless() throws Exception {
        scan("https://example.com/?q='OR'1'='1;DROP-TABLE-scans;--");
        mvc.perform(get("/history").param("level", "' OR 1=1--")).andExpect(status().isOk());
        mvc.perform(get("/history")).andExpect(content().string(containsString("example.com")));
    }

    @Test void detailAnd404() throws Exception {
        MvcResult r = scan("http://example.com:4444/");
        mvc.perform(get(r.getResponse().getRedirectedUrl())).andExpect(content().string(containsString("Unusual port")));
        mvc.perform(get("/history/99999")).andExpect(status().isNotFound());
        mvc.perform(get("/nope")).andExpect(status().isNotFound());
    }

    @Test void filterAndPagination() throws Exception {
        for (int i = 0; i < 12; i++) scan("https://site" + i + ".example.com/");
        scan("http://1.2.3.4:99/login/verify/account/setup.exe");
        mvc.perform(get("/history")).andExpect(content().string(containsString("page 1 of 2")));
        mvc.perform(get("/history").param("page", "2")).andExpect(content().string(containsString("page 2 of 2")));
        mvc.perform(get("/history").param("level", "High Risk"))
           .andExpect(content().string(containsString("1.2.3.4")))
           .andExpect(content().string(not(containsString("site1.example.com"))));
        mvc.perform(get("/history").param("from", "2999-01-01")).andExpect(content().string(containsString("No scans match")));
    }

    @Test void dashboardEmptyAndWithData() throws Exception {
        mvc.perform(get("/dashboard")).andExpect(content().string(containsString("No scans recorded yet")));
        scan("https://example.com/");
        scan("https://example.org/");
        scan("http://1.2.3.4:99/login/verify/account/setup.exe");
        mvc.perform(get("/dashboard"))
           .andExpect(content().string(containsString("id=\"stat-total\">3<")))
           .andExpect(content().string(containsString("id=\"stat-low\">2<")))
           .andExpect(content().string(containsString("id=\"stat-high\">1<")));
    }

    @Test void clearHistoryNeedsConfirmation() throws Exception {
        scan("https://example.com/");
        mvc.perform(post("/history/clear").with(csrf()));
        mvc.perform(get("/history")).andExpect(content().string(containsString("example.com")));
        mvc.perform(post("/history/clear").with(csrf()).param("confirm", "yes"));
        mvc.perform(get("/history")).andExpect(content().string(containsString("No scans")));
    }

    @Test void qrUploadFlows() throws Exception {
        MockMultipartFile url = new MockMultipartFile("qr_image", "qr.png", "image/png", QrTestImages.png("http://1.2.3.4/login"));
        mvc.perform(multipart("/qr-scanner").file(url).with(csrf()).param("save_history", "on"))
           .andExpect(status().isOk()).andExpect(content().string(containsString("Medium Risk")))
           .andExpect(content().string(containsString("http://1.2.3.4/login")));
        MockMultipartFile text = new MockMultipartFile("qr_image", "qr.png", "image/png", QrTestImages.png("just words"));
        mvc.perform(multipart("/qr-scanner").file(text).with(csrf())).andExpect(content().string(containsString("plain text")));
        MockMultipartFile js = new MockMultipartFile("qr_image", "qr.png", "image/png", QrTestImages.png("javascript:alert(1)"));
        mvc.perform(multipart("/qr-scanner").file(js).with(csrf())).andExpect(content().string(containsString("other than http/https")));
        mvc.perform(get("/history")).andExpect(content().string(containsString("QR")));
    }

    @Test void badUploadsAreRejected() throws Exception {
        byte[] png = QrTestImages.png("x");
        mvc.perform(multipart("/qr-scanner").file(new MockMultipartFile("qr_image", "a.png", "image/png", "garbage".getBytes())).with(csrf()))
           .andExpect(status().isBadRequest());
        mvc.perform(multipart("/qr-scanner").file(new MockMultipartFile("qr_image", "a.exe", "image/png", png)).with(csrf()))
           .andExpect(status().isBadRequest());
        mvc.perform(multipart("/qr-scanner").file(new MockMultipartFile("qr_image", "a.png", "text/html", png)).with(csrf()))
           .andExpect(status().isBadRequest());
        mvc.perform(multipart("/qr-scanner").file(new MockMultipartFile("qr_image", "a.png", "image/png", new byte[0])).with(csrf()))
           .andExpect(status().isBadRequest());
    }

    @Test void csrfIsEnforcedAndHeadersPresent() throws Exception {
        mvc.perform(post("/scan").param("url", "https://example.com")).andExpect(status().isForbidden());
        mvc.perform(get("/")).andExpect(header().string("X-Content-Type-Options", "nosniff"))
           .andExpect(header().string("Content-Security-Policy", containsString("default-src 'self'")));
    }
}
