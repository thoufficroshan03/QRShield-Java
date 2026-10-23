package com.qrshield.web;

import com.qrshield.core.AnalysisResult;
import com.qrshield.data.ScanView;
import com.qrshield.qr.QrReader;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.multipart.MultipartFile;

@Controller
@RequestMapping("/qr-scanner")
public class QrController {
    private static final Set<String> ALLOWED_EXTENSIONS = Set.of("png", "jpg", "jpeg", "gif", "bmp");

    public record QrEntry(String text, String kind, ScanView scan, Long scanId, String error) {}

    private final ScanService scanService;
    private final QrShieldProperties props;

    public QrController(ScanService scanService, QrShieldProperties props) {
        this.scanService = scanService;
        this.props = props;
    }

    @GetMapping
    public String form() { return "qr_scanner"; }

    private String fail(Model model, HttpServletResponse response, String message) {  // helper – no mapping
        model.addAttribute("error", message);
        response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
        return "qr_scanner";
    }

    @PostMapping
    public String submit(@RequestParam(name = "qr_image", required = false) MultipartFile file,
                         @RequestParam(name = "save_history", required = false) String saveHistory,
                         Model model, HttpServletResponse response) throws IOException {
        // Store once to avoid double-call and satisfy null-safety analysis
        String originalName = (file == null) ? null : file.getOriginalFilename();
        if (file == null || originalName == null || originalName.isBlank()) {
            return fail(model, response, "Please choose an image file to upload.");
        }
        if (file.isEmpty()) return fail(model, response, "The uploaded file is empty.");
        String ext = StringUtils.getFilenameExtension(originalName); // name used ONLY for extension check
        String type = Objects.requireNonNullElse(file.getContentType(), "");
        if (ext == null || !ALLOWED_EXTENSIONS.contains(ext.toLowerCase()) || !type.startsWith("image/")) {
            return fail(model, response, "Unsupported file type. Upload a PNG, JPEG, GIF or BMP image.");
        }

        Path dir = Path.of(props.getTmpDir());
        Files.createDirectories(dir);
        Path tmp = Objects.requireNonNull(Files.createTempFile(dir, "qr-", ".bin"),
                "createTempFile should never return null"); // random name; user filename is never used
        QrReader.QrResult result;
        try {
            file.transferTo(tmp); // tmp is always non-null: createTempFile never returns null
            result = QrReader.decode(tmp, props.getMaxImagePixels());
        } finally {
            Files.deleteIfExists(tmp); // uploads are never kept
        }
        if (!result.ok()) return fail(model, response, result.error());

        boolean save = saveHistory != null;
        List<QrEntry> entries = new ArrayList<>();
        String warning = null;
        for (String text : result.codes()) {
            String kind = QrReader.classify(text);
            ScanView view = null;
            Long scanId = null;
            String error = null;
            if (kind.equals("url")) {
                ScanService.Outcome outcome = scanService.analyzeAndStore(text, "qr", save);
                AnalysisResult analysis = outcome.analysis();
                scanId = outcome.scanId();
                if (outcome.warning() != null && warning == null) warning = outcome.warning();
                if (analysis.valid()) view = scanService.toView(analysis, scanId, "qr");
                else error = analysis.error();
            }
            entries.add(new QrEntry(text, kind, view, scanId, error));
        }
        model.addAttribute("entries", entries);
        model.addAttribute("warning", warning);
        return "qr_scanner";
    }
}
