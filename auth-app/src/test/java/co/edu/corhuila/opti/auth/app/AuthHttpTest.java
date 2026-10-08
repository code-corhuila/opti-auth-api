package co.edu.corhuila.opti.auth.app;

import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.containsString;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.time.Duration;
import java.util.List;
import java.util.UUID;

import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;

import com.fasterxml.jackson.databind.ObjectMapper;

/** Contract checks of user management plus the sign-in, password and service-token rules of this domain. */
class AuthHttpTest extends ContractChecks {

    private static final String PASSWORD = "Correct-Horse-42";
    private static final ObjectMapper JSON = new ObjectMapper();

    @Override
    protected String collectionPath() {
        return "/api/v1/users";
    }

    @Override
    protected String writerRole() {
        return "ADMIN";
    }

    @Override
    protected String strangerRole() {
        return "SELLER";
    }

    @Override
    protected String validBody(int n) {
        return userJson("user." + n, PASSWORD);
    }

    @Override
    protected String invalidBody() {
        return """
                {"username":"A!","fullName":" ","password":"short"}""";
    }

    @Override
    protected List<String> invalidBodyFields() {
        return List.of("username", "fullName", "password", "role");
    }

    // ---- login ----------------------------------------------------------------------------

    @Test
    void loginIsPublicAndTheTokenItReturnsIsAcceptedByTheSameService() throws Exception {
        String username = "login." + next();
        createUser(username);

        String token = accessToken(login(username, PASSWORD)
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.tokenType").value("Bearer"))
                .andExpect(jsonPath("$.expiresIn").value(3600))
                .andExpect(jsonPath("$.user.username").value(username))
                .andExpect(jsonPath("$.user.role").value("SELLER"))
                .andExpect(content().string(not(containsString("passwordHash"))))
                .andReturn().getResponse().getContentAsString());

        mvc.perform(get("/api/v1/auth/me").header("Authorization", "Bearer " + token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.username").value(username));
    }

    @Test
    void wrongPasswordAndUnknownUserAnswerTheSame401() throws Exception {
        String username = "wrong." + next();
        createUser(username);

        for (String[] attempt : new String[][] {{username, "Wrong-Password-1"}, {"nobody." + next(), PASSWORD}}) {
            login(attempt[0], attempt[1])
                    .andExpect(status().isUnauthorized())
                    .andExpect(jsonPath("$.error").value("UNAUTHORIZED"))
                    .andExpect(jsonPath("$.message").value("invalid credentials"))
                    .andExpect(jsonPath("$.traceId").exists());
        }
    }

    @Test
    void fiveWrongPasswordsLockTheUser() throws Exception {
        String username = "lock." + next();
        createUser(username);

        for (int i = 0; i < 5; i++) {
            login(username, "Wrong-Password-1").andExpect(status().isUnauthorized());
        }
        login(username, PASSWORD).andExpect(status().isUnauthorized());
        clock.advance(Duration.ofMinutes(16));
        login(username, PASSWORD).andExpect(status().isOk());
    }

    @Test
    void loginBodyIsValidatedFieldByField() throws Exception {
        mvc.perform(post("/api/v1/auth/login").contentType(MediaType.APPLICATION_JSON).content("{\"username\":\" \"}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.details[*].field", hasItem("username")))
                .andExpect(jsonPath("$.details[*].field", hasItem("password")));
        mvc.perform(post("/api/v1/auth/login").contentType(MediaType.APPLICATION_JSON).content("{ nope"))
                .andExpect(status().isBadRequest());
    }

    @Test
    void anInactiveUserCannotLogInAndYouCannotDeactivateYourself() throws Exception {
        String username = "inactive." + next();
        String id = createUser(username);
        String adminToken = accessToken(loginAsSelf("admin." + next()));

        mvc.perform(post(collectionPath() + "/" + id + "/deactivate").header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isOk()).andExpect(jsonPath("$.active").value(false));
        login(username, PASSWORD).andExpect(status().isUnauthorized());
        mvc.perform(post(collectionPath() + "/" + id + "/activate").header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isOk()).andExpect(jsonPath("$.active").value(true));
        login(username, PASSWORD).andExpect(status().isOk());
    }

    @Test
    void anAdministratorCannotDeactivateOwnUser() throws Exception {
        String username = "self." + next();
        String id = idOf(mvc.perform(create(adminJson(username), "key-" + UUID.randomUUID())
                        .header("Authorization", "Bearer " + TestTokens.valid(clock.instant(), "ADMIN")))
                .andReturn().getResponse().getContentAsString());
        String token = accessToken(login(username, PASSWORD).andReturn().getResponse().getContentAsString());

        mvc.perform(post(collectionPath() + "/" + id + "/deactivate").header("Authorization", "Bearer " + token))
                .andExpect(status().isUnprocessableEntity())
                .andExpect(jsonPath("$.error").value("BUSINESS_RULE_VIOLATION"));
    }

    // ---- roles ----------------------------------------------------------------------------

    @Test
    void onlyAdministratorsManageUsers() throws Exception {
        for (String role : List.of("SELLER", "OPTOMETRIST", "SERVICE")) {
            as(post(collectionPath() + "/" + UUID.randomUUID() + "/deactivate"), role).andExpect(status().isForbidden());
            as(put(collectionPath() + "/" + UUID.randomUUID() + "/sales-goal").contentType(MediaType.APPLICATION_JSON)
                    .content("{\"salesGoalCents\":1000}"), role).andExpect(status().isForbidden());
        }
        for (String role : List.of("SELLER", "OPTOMETRIST")) {
            as(get(collectionPath()), role).andExpect(status().isForbidden());
            as(get(collectionPath() + "/" + UUID.randomUUID()), role).andExpect(status().isForbidden());
        }
    }

    /** The worker reads the user list to check sales goals; it never manages users. */
    @Test
    void theServiceRoleOnlyReadsUsers() throws Exception {
        as(get(collectionPath() + "?role=SELLER"), "SERVICE").andExpect(status().isOk());
        as(get(collectionPath() + "/" + UUID.randomUUID()), "SERVICE").andExpect(status().isNotFound());
    }

    @Test
    void listFiltersAreValidated() throws Exception {
        as(get(collectionPath() + "?role=BOSS"), "ADMIN").andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.details[0].field").value("role"));
        as(get(collectionPath() + "?active=maybe"), "ADMIN").andExpect(status().isBadRequest());
        as(get(collectionPath() + "?role=SELLER&active=true"), "ADMIN").andExpect(status().isOk());
    }

    @Test
    void duplicateUsernameWithAnotherKeyIsABusinessRuleViolation() throws Exception {
        String username = "dup." + next();
        createUser(username);

        as(create(userJson(username, PASSWORD), "key-" + UUID.randomUUID()), "ADMIN")
                .andExpect(status().isUnprocessableEntity())
                .andExpect(jsonPath("$.error").value("BUSINESS_RULE_VIOLATION"));
    }

    // ---- password and service tokens ------------------------------------------------------

    @Test
    void changePasswordWorksWithTheOwnToken() throws Exception {
        String username = "change." + next();
        createUser(username);
        String token = accessToken(login(username, PASSWORD).andReturn().getResponse().getContentAsString());

        mvc.perform(post("/api/v1/auth/change-password").header("Authorization", "Bearer " + token)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"currentPassword\":\"Wrong-Password-1\",\"newPassword\":\"Another-Pass-77\"}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.details[0].field").value("currentPassword"));
        mvc.perform(post("/api/v1/auth/change-password").header("Authorization", "Bearer " + token)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"currentPassword\":\"" + PASSWORD + "\",\"newPassword\":\"Another-Pass-77\"}"))
                .andExpect(status().isNoContent());

        login(username, "Another-Pass-77").andExpect(status().isOk());
        login(username, PASSWORD).andExpect(status().isUnauthorized());
    }

    @Test
    void meNeedsAUserToken() throws Exception {
        as(get("/api/v1/auth/me"), "SERVICE").andExpect(status().isNotFound());
        mvc.perform(get("/api/v1/auth/me")).andExpect(status().isUnauthorized());
    }

    @Test
    void serviceTokensAreIssuedToAdministratorsOnly() throws Exception {
        as(post("/api/v1/auth/service-tokens").contentType(MediaType.APPLICATION_JSON)
                .content("{\"name\":\"opti-worker\",\"ttlDays\":30}"), "SELLER").andExpect(status().isForbidden());

        String body = as(post("/api/v1/auth/service-tokens").contentType(MediaType.APPLICATION_JSON)
                .content("{\"name\":\"opti-worker\",\"ttlDays\":30}"), "ADMIN")
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.tokenType").value("Bearer"))
                .andExpect(jsonPath("$.expiresIn").value(30 * 86400))
                .andReturn().getResponse().getContentAsString();

        // the service token is a real, verifiable token carrying the SERVICE role
        mvc.perform(get(collectionPath()).header("Authorization", "Bearer " + accessToken(body)))
                .andExpect(status().isForbidden());
        as(post("/api/v1/auth/service-tokens").contentType(MediaType.APPLICATION_JSON)
                .content("{\"name\":\"Bad Name!\",\"ttlDays\":91}"), "ADMIN")
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.details[*].field", hasItem("name")))
                .andExpect(jsonPath("$.details[*].field", hasItem("ttlDays")));
    }

    // ---- helpers --------------------------------------------------------------------------

    private org.springframework.test.web.servlet.ResultActions login(String username, String password) throws Exception {
        return mvc.perform(post("/api/v1/auth/login").contentType(MediaType.APPLICATION_JSON)
                .content("{\"username\":\"" + username + "\",\"password\":\"" + password + "\"}"));
    }

    /** Creates an administrator and logs in as it, returning the login response body. */
    private String loginAsSelf(String username) throws Exception {
        as(create(adminJson(username), "key-" + UUID.randomUUID()), "ADMIN").andExpect(status().isCreated());
        return login(username, PASSWORD).andExpect(status().isOk()).andReturn().getResponse().getContentAsString();
    }

    private String createUser(String username) throws Exception {
        return idOf(as(create(userJson(username, PASSWORD), "key-" + UUID.randomUUID()), "ADMIN")
                .andExpect(status().isCreated()).andReturn().getResponse().getContentAsString());
    }

    private static String accessToken(String responseBody) throws Exception {
        return JSON.readTree(responseBody).path("accessToken").asText();
    }

    private static String userJson(String username, String password) {
        return "{\"username\":\"%s\",\"fullName\":\"Laura Ortega\",\"password\":\"%s\",\"role\":\"SELLER\"}"
                .formatted(username, password);
    }

    private static String adminJson(String username) {
        return "{\"username\":\"%s\",\"fullName\":\"Ana Admin\",\"password\":\"%s\",\"role\":\"ADMIN\"}"
                .formatted(username, PASSWORD);
    }
}
