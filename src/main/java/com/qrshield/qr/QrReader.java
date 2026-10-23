package com.qrshield.qr;

import com.google.zxing.BinaryBitmap;
import com.google.zxing.DecodeHintType;
import com.google.zxing.BarcodeFormat;
import com.google.zxing.MultiFormatReader;
import com.google.zxing.NotFoundException;
import com.google.zxing.Result;
import com.google.zxing.client.j2se.BufferedImageLuminanceSource;
import com.google.zxing.common.GlobalHistogramBinarizer;
import com.google.zxing.common.HybridBinarizer;
import com.google.zxing.multi.GenericMultipleBarcodeReader;
import java.awt.Color;
import java.awt.Graphics2D;
import java.awt.RenderingHints;
import java.awt.image.BufferedImage;
import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.EnumMap;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;
import javax.imageio.ImageIO;
import javax.imageio.ImageReader;
import javax.imageio.stream.ImageInputStream;

/**
 * Safe QR decoding: validates the image first (format, pixel count), then
 * decodes using multiple ZXing strategies so QR codes surrounded by text,
 * printed in dark images, or placed off-centre are detected reliably.
 *
 * Strategies tried (in order, stops as soon as any code is found):
 *   1. Flat-white  + HybridBinarizer        (original approach)
 *   2. Flat-white  + HybridBinarizer + TRY_HARDER + padding
 *   3. Flat-white  + GlobalHistogramBinarizer (handles low-contrast images)
 *   4. Inverted    + HybridBinarizer         (dark-background QR codes)
 *   5. Inverted    + GlobalHistogramBinarizer
 *   6. Scaled ×2   + HybridBinarizer         (tiny QR codes)
 *   7. Scaled ×0.5 + HybridBinarizer         (very large / padded images)
 *   8. Centre crop (60 %) + HybridBinarizer  (text header/footer present)
 *   9. Centre crop (80 %) + HybridBinarizer
 *  10. Centre crop (40 %) + HybridBinarizer
 */
public final class QrReader {
    public static final int MAX_CODES = 10;
    public static final int MAX_TEXT  = 4096;
    private static final Set<String> ALLOWED_FORMATS = Set.of("PNG", "JPEG", "GIF", "BMP");
    private static final Pattern URL         = Pattern.compile("^https?://.*", Pattern.CASE_INSENSITIVE | Pattern.DOTALL);
    private static final Pattern SCHEME_LIKE = Pattern.compile("^[A-Za-z][A-Za-z0-9+.\\-]*:.*", Pattern.DOTALL);

    public record QrResult(boolean ok, List<String> codes, String error) {
        static QrResult fail(String message) { return new QrResult(false, List.of(), message); }
    }

    private QrReader() {}

    /** "url" (http/https), "unsupported_scheme" or "text". */
    public static String classify(String text) {
        if (URL.matcher(text).matches()) return "url";
        if (SCHEME_LIKE.matcher(text).matches()) return "unsupported_scheme";
        return "text";
    }

    // ── Public entry point ─────────────────────────────────────────────────
    public static QrResult decode(Path file, long maxPixels) {
        BufferedImage image = loadImage(file, maxPixels);
        if (image == null) return QrResult.fail("The file is not a valid, readable image.");

        BufferedImage flat    = flattenOnWhite(image);
        BufferedImage inv     = invert(flat);
        BufferedImage scaled2 = scale(flat, 2.0);
        BufferedImage half    = scale(flat, 0.5);

        // All variants to try; cropped regions handle text above/below the QR
        List<BufferedImage> variants = new ArrayList<>();
        variants.add(flat);
        variants.add(pad(flat, 40));
        variants.add(inv);
        variants.add(scaled2);
        variants.add(half);
        variants.add(centreCrop(flat, 0.60));   // removes ≈20 % header + footer
        variants.add(centreCrop(flat, 0.80));   // removes ≈10 % header + footer
        variants.add(centreCrop(flat, 0.40));   // tight crop when QR is small
        variants.add(pad(centreCrop(flat, 0.60), 30)); // cropped + padded
        variants.add(centreCrop(inv,  0.60));   // inverted + cropped

        for (BufferedImage v : variants) {
            if (v == null) continue;
            Set<String> codes = decodeAll(v);
            if (!codes.isEmpty()) {
                return new QrResult(true, codes.stream()
                        .limit(MAX_CODES)
                        .map(c -> c.length() > MAX_TEXT ? c.substring(0, MAX_TEXT) : c)
                        .toList(), "");
            }
        }
        return QrResult.fail("No QR code could be detected in this image. "
                + "Make sure the image contains a clear QR code and try cropping out any text borders.");
    }

    // ── Decode one image variant with both binarizers ─────────────────────
    private static Set<String> decodeAll(BufferedImage image) {
        Map<DecodeHintType, Object> hints = new EnumMap<>(DecodeHintType.class);
        hints.put(DecodeHintType.TRY_HARDER, Boolean.TRUE);
        hints.put(DecodeHintType.POSSIBLE_FORMATS, List.of(BarcodeFormat.QR_CODE));

        Set<String> found = new LinkedHashSet<>();
        var src = new BufferedImageLuminanceSource(image);

        // Try HybridBinarizer (works best for most photos)
        found.addAll(tryDecode(new BinaryBitmap(new HybridBinarizer(src)), hints));
        if (!found.isEmpty()) return found;

        // Fallback: GlobalHistogramBinarizer (better for low contrast / printed docs)
        found.addAll(tryDecode(new BinaryBitmap(new GlobalHistogramBinarizer(src)), hints));
        return found;
    }

    private static Set<String> tryDecode(BinaryBitmap bitmap, Map<DecodeHintType, Object> hints) {
        Set<String> found = new LinkedHashSet<>();
        try {
            Result[] results = new GenericMultipleBarcodeReader(new MultiFormatReader())
                    .decodeMultiple(bitmap, hints);
            for (Result r : results) {
                if (r.getText() != null && !r.getText().isBlank()) found.add(r.getText().strip());
            }
        } catch (NotFoundException ignored) {}
        return found;
    }

    // ── Image transformation helpers ──────────────────────────────────────

    /** Flatten alpha onto white background, convert to RGB. */
    private static BufferedImage flattenOnWhite(BufferedImage src) {
        BufferedImage out = new BufferedImage(src.getWidth(), src.getHeight(), BufferedImage.TYPE_INT_RGB);
        Graphics2D g = out.createGraphics();
        g.setColor(Color.WHITE);
        g.fillRect(0, 0, out.getWidth(), out.getHeight());
        g.drawImage(src, 0, 0, null);
        g.dispose();
        return out;
    }

    /** Add a white border so codes near the edge are detected. */
    private static BufferedImage pad(BufferedImage src, int border) {
        if (src == null) return null;
        BufferedImage out = new BufferedImage(
                src.getWidth()  + 2 * border,
                src.getHeight() + 2 * border,
                BufferedImage.TYPE_INT_RGB);
        Graphics2D g = out.createGraphics();
        g.setColor(Color.WHITE);
        g.fillRect(0, 0, out.getWidth(), out.getHeight());
        g.drawImage(src, border, border, null);
        g.dispose();
        return out;
    }

    /** Invert colours (dark background / white QR modules). */
    private static BufferedImage invert(BufferedImage src) {
        if (src == null) return null;
        BufferedImage out = new BufferedImage(src.getWidth(), src.getHeight(), BufferedImage.TYPE_INT_RGB);
        for (int y = 0; y < src.getHeight(); y++) {
            for (int x = 0; x < src.getWidth(); x++) {
                int rgb = src.getRGB(x, y);
                out.setRGB(x, y, 0xFFFFFF ^ (rgb & 0xFFFFFF));
            }
        }
        return out;
    }

    /** Scale the image by a factor (bilinear for quality). */
    private static BufferedImage scale(BufferedImage src, double factor) {
        if (src == null) return null;
        int w = Math.max(1, (int)(src.getWidth()  * factor));
        int h = Math.max(1, (int)(src.getHeight() * factor));
        BufferedImage out = new BufferedImage(w, h, BufferedImage.TYPE_INT_RGB);
        Graphics2D g = out.createGraphics();
        g.setRenderingHint(RenderingHints.KEY_INTERPOLATION, RenderingHints.VALUE_INTERPOLATION_BILINEAR);
        g.setColor(Color.WHITE);
        g.fillRect(0, 0, w, h);
        g.drawImage(src, 0, 0, w, h, null);
        g.dispose();
        return out;
    }

    /**
     * Crop the centre fraction of the image.
     * e.g. fraction=0.60 → keep the middle 60 % width and 60 % height.
     * This removes text that appears as a header/footer or side caption
     * around the QR code, which confuses ZXing's region detector.
     */
    private static BufferedImage centreCrop(BufferedImage src, double fraction) {
        if (src == null) return null;
        int W = src.getWidth();
        int H = src.getHeight();
        int cw = (int)(W * fraction);
        int ch = (int)(H * fraction);
        if (cw < 10 || ch < 10) return null;
        int x = (W - cw) / 2;
        int y = (H - ch) / 2;
        return src.getSubimage(x, y, cw, ch);
    }

    // ── Image loading ──────────────────────────────────────────────────────
    private static BufferedImage loadImage(Path file, long maxPixels) {
        try (ImageInputStream in = ImageIO.createImageInputStream(file.toFile())) {
            if (in == null) return null;
            Iterator<ImageReader> readers = ImageIO.getImageReaders(in);
            if (!readers.hasNext()) return null;
            ImageReader reader = readers.next();
            try {
                reader.setInput(in);
                if (!ALLOWED_FORMATS.contains(reader.getFormatName().toUpperCase())) return null;
                long pixels = (long) reader.getWidth(0) * reader.getHeight(0);
                if (pixels > maxPixels) return null;
                return reader.read(0);
            } finally {
                reader.dispose();
            }
        } catch (IOException | RuntimeException e) {
            return null;
        }
    }
}
