package com.qrshield.web;

import com.qrshield.data.ScanRepository;
import com.qrshield.data.ScanView;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DataAccessException;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;
import org.springframework.web.server.ResponseStatusException;
import jakarta.servlet.http.HttpServletResponse;

@Controller
public class HistoryController {
    private static final Logger log = LoggerFactory.getLogger(HistoryController.class);
    private final ScanRepository repository;
    private final QrShieldProperties props;

    public HistoryController(ScanRepository repository, QrShieldProperties props) {
        this.repository = repository;
        this.props = props;
    }

    private String dbError(Model model, HttpServletResponse response, String what) {
        model.addAttribute("title", "Database unavailable");
        model.addAttribute("message", what + " could not be loaded right now. Please try again.");
        response.setStatus(HttpServletResponse.SC_SERVICE_UNAVAILABLE);
        return "problem";
    }

    @GetMapping("/history")
    public String history(@RequestParam(name = "level", defaultValue = "") String level,
                          @RequestParam(name = "from", defaultValue = "") String from,
                          @RequestParam(name = "to", defaultValue = "") String to,
                          @RequestParam(name = "page", defaultValue = "1") int page,
                          Model model, HttpServletResponse response) {
        try {
            ScanRepository.ScanPage result = repository.list(level, from, to, page, props.getPageSize());
            long pages = Math.max(1, (result.total() + props.getPageSize() - 1) / props.getPageSize());
            model.addAttribute("scans", result.rows());
            model.addAttribute("total", result.total());
            model.addAttribute("page", Math.max(page, 1));
            model.addAttribute("pages", pages);
            model.addAttribute("level", level);
            model.addAttribute("from", from);
            model.addAttribute("to", to);
            model.addAttribute("levels", ScanRepository.LEVELS);
            return "history";
        } catch (DataAccessException e) {
            log.error("History query failed", e);
            return dbError(model, response, "History");
        }
    }

    @GetMapping({"/history/{id}", "/result/{id}"})
    public String result(@PathVariable long id, Model model, HttpServletResponse response) {
        try {
            ScanView scan = repository.find(id).orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND));
            model.addAttribute("scan", scan);
            return "result";
        } catch (DataAccessException e) {
            log.error("Result query failed", e);
            return dbError(model, response, "This record");
        }
    }

    @PostMapping("/history/clear")
    public String clear(@RequestParam(name = "confirm", required = false) String confirm,
                        RedirectAttributes redirect, Model model, HttpServletResponse response) {
        if (!"yes".equals(confirm)) {
            redirect.addFlashAttribute("flashType", "warning");
            redirect.addFlashAttribute("flash", "Tick the confirmation box to clear history.");
            return "redirect:/history";
        }
        try {
            repository.clear();
        } catch (DataAccessException e) {
            log.error("Clear failed", e);
            return dbError(model, response, "History");
        }
        redirect.addFlashAttribute("flashType", "success");
        redirect.addFlashAttribute("flash", "Scan history cleared.");
        return "redirect:/history";
    }
}
