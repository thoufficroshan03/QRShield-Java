package com.qrshield.web;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.qrshield.data.ScanRepository;
import java.util.Map;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DataAccessException;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class DashboardController {
    private static final Logger log = LoggerFactory.getLogger(DashboardController.class);
    private final ScanRepository repository;
    private final ObjectMapper mapper = new ObjectMapper();

    public DashboardController(ScanRepository repository) { this.repository = repository; }

    @GetMapping("/dashboard")
    public String dashboard(Model model, HttpServletResponse response) throws JsonProcessingException {
        try {
            ScanRepository.Stats stats = repository.stats(14);
            model.addAttribute("stats", stats);
            // JSON goes into data-* attributes (escaped by Thymeleaf), read by main.js: no inline scripts needed
            model.addAttribute("levelsJson", mapper.writeValueAsString(stats.byLevel()));
            model.addAttribute("trendJson", mapper.writeValueAsString(
                    Map.of("labels", stats.trendLabels(), "values", stats.trendValues())));
            return "dashboard";
        } catch (DataAccessException e) {
            log.error("Dashboard query failed", e);
            model.addAttribute("title", "Database unavailable");
            model.addAttribute("message", "Statistics could not be loaded right now.");
            response.setStatus(HttpServletResponse.SC_SERVICE_UNAVAILABLE);
            return "problem";
        }
    }
}
