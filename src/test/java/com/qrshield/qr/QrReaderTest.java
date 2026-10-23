package com.qrshield.qr;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.awt.image.BufferedImage;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class QrReaderTest {
    @TempDir Path dir;

    private QrReader.QrResult decode(byte[] bytes, long maxPixels) throws Exception {
        Path file = dir.resolve("f.bin");
        Files.write(file, bytes);
        return QrReader.decode(file, maxPixels);
    }

    @Test void qrWithUrl() throws Exception {
        var r = decode(QrTestImages.png("https://example.com/a"), 12_000_000);
        assertTrue(r.ok());
        assertEquals(List.of("https://example.com/a"), r.codes());
    }

    @Test void qrWithPlainTextAndClassification() throws Exception {
        var r = decode(QrTestImages.png("hello world"), 12_000_000);
        assertTrue(r.ok());
        assertEquals("text", QrReader.classify(r.codes().get(0)));
        assertEquals("url", QrReader.classify("HTTPS://x.com"));
        assertEquals("unsupported_scheme", QrReader.classify("javascript:alert(1)"));
        assertEquals("unsupported_scheme", QrReader.classify("WIFI:S:x;;"));
    }

    @Test void multipleCodes() throws Exception {
        var r = decode(QrTestImages.twoCodes("https://one.example/", "https://two.example/"), 12_000_000);
        assertTrue(r.ok());
        assertEquals(Set.of("https://one.example/", "https://two.example/"), Set.copyOf(r.codes()));
    }

    @Test void invalidCorruptAndEmptyImages() throws Exception {
        assertFalse(decode("not an image".getBytes(), 12_000_000).ok());
        byte[] png = QrTestImages.png("x");
        assertFalse(decode(java.util.Arrays.copyOf(png, 50), 12_000_000).ok());
    }

    @Test void noQrInImage() throws Exception {
        BufferedImage blank = new BufferedImage(200, 200, BufferedImage.TYPE_INT_RGB);
        var r = decode(QrTestImages.png(blank), 12_000_000);
        assertFalse(r.ok());
        assertTrue(r.error().contains("No QR"));
    }

    @Test void pixelLimit() throws Exception {
        assertTrue(decode(QrTestImages.png("x"), 100).error().contains("too many pixels"));
    }
}
