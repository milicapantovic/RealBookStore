package com.urosdragojevic.realbookstore.controller;

import com.urosdragojevic.realbookstore.audit.AuditLogger;
import com.urosdragojevic.realbookstore.domain.Person;
import com.urosdragojevic.realbookstore.domain.User;
import com.urosdragojevic.realbookstore.repository.PersonRepository;
import com.urosdragojevic.realbookstore.repository.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.context.SecurityContextHolder;

import jakarta.servlet.http.HttpServletRequest;
import java.sql.SQLException;
import java.util.List;

import jakarta.servlet.http.HttpSession;
import java.nio.file.AccessDeniedException;

@Controller
public class PersonsController {

    private static final Logger LOG = LoggerFactory.getLogger(PersonsController.class);
    private static final AuditLogger auditLogger = AuditLogger.getAuditLogger(PersonsController.class);

    private final PersonRepository personRepository;
    private final UserRepository userRepository;

    public PersonsController(PersonRepository personRepository, UserRepository userRepository) {
        this.personRepository = personRepository;
        this.userRepository = userRepository;
    }

    @GetMapping("/persons/{id}")
    @PreAuthorize("hasAuthority('VIEW_PERSON')")
    public String person(@PathVariable int id, Model model, HttpSession session) {
        String csrf = session.getAttribute("CSRF_TOKEN").toString();
        model.addAttribute("CSRF_TOKEN", session.getAttribute("CSRF_TOKEN"));
        model.addAttribute("person", personRepository.get("" + id));
        return "person";
    }

    @GetMapping("/myprofile")
    @PreAuthorize("hasAuthority('VIEW_MY_PROFILE')")
    public String self(Model model, Authentication authentication, HttpSession session) {
        User user = (User) authentication.getPrincipal();
        model.addAttribute("CSRF_TOKEN", session.getAttribute("CSRF_TOKEN"));
        model.addAttribute("person", personRepository.get("" + user.getId()));
        return "person";
    }

    @DeleteMapping("/persons/{id}")
    public ResponseEntity<Void> person(@PathVariable int id) {
        personRepository.delete(id);
        userRepository.delete(id);

        return ResponseEntity.noContent().build();
    }

    @PostMapping("/update-person")
    public String updatePerson(Person person, HttpSession session, @RequestParam("csrfToken") String csrfToken, HttpServletRequest request) throws AccessDeniedException {
        String csrf = session.getAttribute("CSRF_TOKEN").toString();
        if(!csrf.equals(csrfToken)){
            auditLogger.audit("Invalid csrf detected!");
            throw new AccessDeniedException("Forbidden");
        }
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        User user = (User) authentication.getPrincipal();
        boolean hasEditPermission = authentication.getAuthorities().stream().anyMatch(grantedAuthority -> grantedAuthority.getAuthority().equals("UPDATE_PERSON"));
        boolean isSelfUpdate = false;
        int personId = Integer.parseInt(person.getId());
        isSelfUpdate = user.getId() == personId;
        if (!hasEditPermission && !isSelfUpdate) {
            auditLogger.audit("Unauthorized person update request!");
            throw new AccessDeniedException("Can`t update person");
        }
        personRepository.update(person);
        auditLogger.audit("Updated person "+person.toString());
        String referer = request.getHeader("Referer");
        if (referer != null && referer.contains("/myprofile")) {
            return "redirect:/myprofile";
        } else {
            return "redirect:/persons/" + person.getId();
        }
    }

    @GetMapping("/persons")
    @PreAuthorize("hasAuthority('VIEW_PERSONS_LIST')")
    public String persons(Model model) {
        model.addAttribute("persons", personRepository.getAll());
        return "persons";
    }

    @GetMapping(value = "/persons/search", produces = "application/json")
    @PreAuthorize("hasAuthority('VIEW_PERSONS_LIST')")
    @ResponseBody
    public List<Person> searchPersons(@RequestParam String searchTerm) throws SQLException {
        return personRepository.search(searchTerm);
    }
}
