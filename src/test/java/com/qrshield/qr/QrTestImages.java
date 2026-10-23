package com.qrshield.qr;

import com.google.zxing.BarcodeFormat;
import com.google.zxing.client.j2se.MatrixToImageWriter;
import com.google.zxing.qrcode.QRCodeWriter;
import java.awt.Color;
import java.awt.Graphics2D;
import java.awt.image.BufferedImage;
import java.io.ByteArrayOutputStream;
import javax.imageio.ImageIO;

/** Helpers that create QR code PNG images for tests. */
public final class QrTestImages {
    private QrTestImages() {}

    public static BufferedImage qr(String text) throws Exception {
        return MatrixToImageWriter.toBufferedImage(new QRCodeWriter().encode(text, BarcodeFormat.QR_CODE, 250, 250));
    }

    public static byte[] png(BufferedImage image) throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        ImageIO.write(image, "png", out);
        return out.toByteArray();
    }

    public static byte[] png(String text) throws Exception { return png(qr(text)); }

    public static byte[] twoCodes(String a, String b) throws Exception {
        BufferedImage first = qr(a), second = qr(b);
        BufferedImage canvas = new BufferedImage(first.getWidth() + second.getWidth() + 120, first.getHeight() + 80, BufferedImage.TYPE_INT_RGB);
        Graphics2D g = canvas.createGraphics();
        g.setColor(Color.WHITE);
        g.fillRect(0, 0, canvas.getWidth(), canvas.getHeight());
        g.drawImage(first, 40, 40, null);
        g.drawImage(second, first.getWidth() + 80, 40, null);
        g.dispose();
        return png(canvas);
    }
}
