package com.example.oauth;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * @author jintao
 */
@RestController
public class IndexController {
    @GetMapping("/")
    public String test() {
        return "hello world";
    }
}
