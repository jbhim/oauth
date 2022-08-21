package com.example.oauth;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;

/**
 * @author jintao
 */
@RestController
@RequestMapping("/api")
public class TestController {

    @GetMapping("test")
    public Map<String, Object> test() {
        HashMap<String, Object> stringObjectHashMap = new HashMap<>();
        stringObjectHashMap.put("test", "test");
        return stringObjectHashMap;
    }

    @GetMapping("test2")
    public Map<String, Object> test2() {
        HashMap<String, Object> stringObjectHashMap = new HashMap<>();
        stringObjectHashMap.put("test2", "test2");
        return stringObjectHashMap;
    }


    @GetMapping("userinfo")
    public Object userinfo() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        System.out.println(authentication);
        return authentication.getPrincipal();
    }

}
