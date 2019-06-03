package securfirstlesson.demo.controllers;


import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import securfirstlesson.demo.models.User;

import java.util.Arrays;
import java.util.List;

@RestController
public class MainController {

    @GetMapping("/")
    public String home(){
        return "home";
    }

    @GetMapping("/users")
    public List<User> users(){
        return Arrays.asList(new User("asd", "qwe"), new User("zxc", "vbn"));
    }
}
