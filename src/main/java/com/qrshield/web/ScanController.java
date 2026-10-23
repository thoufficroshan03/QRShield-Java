package com.qrshield.web;

import jakarta.servlet.http.HttpServletResponse;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
@RequestMapping("/scan")
public class ScanController {
    private final ScanService scanService;

    public ScanController(ScanService scanService) { this.scanService = scanService; }

    @GetMapping
    public String form(Model model) {
        model.addAttribute("url", "");
        return "scanner";
    }

    @PostMapping
    public String submit(@RequestParam(name = "url", defaultValue = "") String url,
                         @RequestParam(name = "save_history", required = false) String saveHistory,
                         Model model, HttpServletResponse response) {
        boolean save = saveHistory != null;
        ScanService.Outcome outcome = scanService.analyzeAndStore(url, "url", save);
        if (!outcome.analysis().valid()) {
            model.addAttribute("url", url.length() > 2100 ? url.substring(0, 2100) : url);
            model.addAttribute("error", outcome.analysis().error());
            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            return "scanner";
        }
        if (outcome.scanId() != null) return "redirect:/result/" + outcome.scanId();
        model.addAttribute("scan", scanService.toView(outcome.analysis(), null, "url"));
        model.addAttribute("warning", outcome.warning() != null ? outcome.warning()
                : "Not saved to history (you left the box unticked).");
        return "result";
    }
}
