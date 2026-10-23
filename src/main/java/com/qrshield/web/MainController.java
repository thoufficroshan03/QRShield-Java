package com.qrshield.web;

import java.util.Map;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
public class MainController {
    @GetMapping("/")
    public String index() { return "index"; }

    @GetMapping("/about")
    public String about() { return "about"; }

    @GetMapping("/health")
    @ResponseBody
    public Map<String, String> health() { return Map.of("status", "ok"); }
}
