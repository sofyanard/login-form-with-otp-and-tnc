package com.atrbpn.keycloak.spi.otptncvalidator;

import com.atrbpn.keycloak.spi.otptncvalidator.helper.DBHelper;
import com.atrbpn.keycloak.spi.otptncvalidator.helper.PostgresDBHelper;
import com.atrbpn.keycloak.spi.otptncvalidator.tnc.TncRequest;
import com.atrbpn.keycloak.spi.otptncvalidator.tnc.TncResponse;
import com.atrbpn.keycloak.spi.otptncvalidator.tnc.TncRestClient;
import com.fasterxml.jackson.databind.ObjectMapper;

import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.Authenticator;
import org.keycloak.events.Details;
import org.keycloak.events.Errors;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserCredentialModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.credential.PasswordUserCredentialModel;
import org.keycloak.models.utils.FormMessage;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.mail.Message;
import javax.mail.Session;
import javax.mail.Transport;
import javax.mail.internet.InternetAddress;
import javax.mail.internet.MimeMessage;
import javax.naming.Context;
import javax.naming.InitialContext;
import javax.ws.rs.core.HttpHeaders;

import java.net.URLDecoder;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Properties;
import java.util.Random;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * <pre>
 *     com.atrbpn.keycloak.spi.otpvalidator.CustomKeycloakFormAuthenticator
 * </pre>
 *
 * @author Muhammad Edwin < edwin at redhat dot com >
 * 28 Mar 2022 17:13
 */
public class CustomKeycloakFormAuthenticator implements Authenticator {

    private static final Logger log = LoggerFactory.getLogger(CustomKeycloakFormAuthenticator.class);

    private static final String Q_SEARCH_OTP = "select 1 from otp where user_id=? and otp=? \n " +
            " and status=0 and created_date > current_timestamp  - INTERVAL '5 minutes'";

    private static final String Q_SEARCH_LAST_2_IP = "select ip from otp where user_id=? order by created_date desc limit 2;";

    private static final String Q_SEARCH_LAST_6_IP = "select ip from otp where user_id=? order by created_date desc limit 6;";

    private static final String Q_VALIDATE_KANTOR = 
            "SELECT DISTINCT 1 \n" +
            "FROM VIEW_USER_INTERNAL_VALIDATION \n" +
            "WHERE USERNAME = ? \n" +
            "AND KANTORID = ? ";

    private static final String Q_UPDATE_OTP = "UPDATE OTP SET STATUS = 1, KANTOR_ID=?, IP=?  where  user_id=? " +
            "and otp=? \n" +
            "and status=0 and created_date > current_timestamp  - INTERVAL '5 minutes'";
    
    private static final String Q_GET_ROLES =
            "SELECT DISTINCT ROLENAME \n" +
            "FROM VIEW_USER_INTERNAL_ROLE \n" +
            "WHERE USERNAME = ? \n" +
            "AND KANTORID = ? \n" +
            "ORDER by ROLENAME";
    
    private static final String TNC_USER_ATTRIBUTE_KEY = "tnc";

    private static String smtpHost;
    private static String smtpFrom;

    static {
        try {
            Context initCxt =  new InitialContext();

            smtpHost = (String) initCxt.lookup("java:/smtpHost");
            smtpFrom = (String) initCxt.lookup("java:/smtpFrom");
        } catch (Exception ex) {
            log.error("unable to get jndi connection for SMTP or Environment");
            log.error(ex.getMessage(), ex);
        }
    }



    @Override
    public void authenticate(AuthenticationFlowContext authenticationFlowContext) {

        // not bringing username
        if(authenticationFlowContext.getHttpRequest().getFormParameters().get("username") == null
                || authenticationFlowContext.getHttpRequest().getFormParameters().get("username").isEmpty()) {

            authenticationFlowContext.getEvent().error(Errors.USER_NOT_FOUND);
            authenticationFlowContext.forkWithErrorMessage(new FormMessage("summary", "Username atau Password Salah"));
            return;
        }

        // not bringing password
        if(authenticationFlowContext.getHttpRequest().getFormParameters().get("password") == null
                || authenticationFlowContext.getHttpRequest().getFormParameters().get("password").isEmpty()) {
            authenticationFlowContext.getEvent().error(Errors.USER_NOT_FOUND);
            authenticationFlowContext.forkWithErrorMessage(new FormMessage("summary", "Username atau Password Salah"));
            return;
        }
        // capture username
        String username = authenticationFlowContext.getHttpRequest().getFormParameters().getFirst("username").trim();

        try {
            username = URLDecoder.decode(username, "UTF-8");
        } catch (Exception ex) {
            log.error(ex.getMessage());
        }

        // search for corresponding user
        UserModel userModel = authenticationFlowContext.getSession()
                .userStorageManager().getUserByUsername(username, authenticationFlowContext.getRealm());

        log.info(" fetching userModel for username : {} ", username);

        // user not exists
        if(userModel == null) {
            log.info(" invalid userModel for username : {} ", username);

            authenticationFlowContext.getEvent().error(Errors.USER_NOT_FOUND);
            authenticationFlowContext.forkWithErrorMessage(new FormMessage("summary", "Username atau Password Salah"));
            return;
        }

        log.info(" fetching password for username : {} ", username);

        String password = authenticationFlowContext.getHttpRequest().getFormParameters().getFirst("password").trim();
        try {
            password = URLDecoder.decode(password, "UTF-8");
        } catch (Exception ex) {
            log.error(ex.getMessage());
        }

        // password is incorrect
        PasswordUserCredentialModel credentialInput = UserCredentialModel.password(password);
        boolean valid = authenticationFlowContext.getSession().userCredentialManager().isValid(authenticationFlowContext.getRealm(),
                userModel,
                new PasswordUserCredentialModel[]{credentialInput} );
        if( !valid ) {
            log.info(" invalid password for username : {} ", username);

            authenticationFlowContext.getEvent().error(Errors.USER_NOT_FOUND);
            authenticationFlowContext.forkWithErrorMessage(new FormMessage("summary", "Username atau Password Salah"));
            return;
        }

        log.info(" fetching otp for username : {} ", username);

        //  get otp
        String otp = authenticationFlowContext.getHttpRequest().getFormParameters().getFirst("otp").trim();

        // not bringing otp
        if(otp == null
                || otp.isEmpty()) {
            log.info(" invalid otp for username : {} ", username);

            authenticationFlowContext.getEvent().error(Errors.USER_NOT_FOUND);
            authenticationFlowContext.forkWithErrorMessage(new FormMessage("summary", "OTP tidak ditemukan atau salah"));
            return;
        }

        //  search for otp
        if(!isUserAndOtpExist(userModel.getUsername(), otp)) {
            authenticationFlowContext.getEvent().error(Errors.USER_NOT_FOUND);
            authenticationFlowContext.forkWithErrorMessage(new FormMessage("summary", "OTP tidak ditemukan atau salah"));
            return;
        }

        log.info(" fetching kantor for username : {} ", username);

        String kantor = authenticationFlowContext.getHttpRequest().getFormParameters().getFirst("kantor").trim();
        if(!isUserAndKantorExist(userModel.getUsername(), kantor)) {
            log.info(" invalid kantor for username : {} ", username);

            authenticationFlowContext.getEvent().error(Errors.USER_NOT_FOUND);
            authenticationFlowContext.forkWithErrorMessage(new FormMessage("summary", "Kantor tidak ditemukan atau salah"));
            return;
        }

        log.info(" fetching roles for username : {} and kantor : {} ", username, kantor);

        List<String> roles = new ArrayList<>();
        roles = getRoles(userModel.getUsername(), kantor);
        if (roles.isEmpty()) {
            log.info(" roles not found for username : {} and kantor : {} ", username, kantor);

            authenticationFlowContext.getEvent().error(Errors.USER_NOT_FOUND);
            authenticationFlowContext.forkWithErrorMessage(new FormMessage("summary", "Role tidak ditemukan"));
            return;
        }

        // capture the ip from X-Forwarded-For header
        String ip = authenticationFlowContext.getHttpRequest().getHttpHeaders().getHeaderString("X-Forwarded-For");
        if(ip ==null)
            ip = authenticationFlowContext.getSession().getContext().getConnection().getRemoteAddr();

        // update kantor into table and invalidate OTP
        updateOtp(username, otp, kantor, ip);

        // validate remember me
        String rememberMe = authenticationFlowContext.getHttpRequest().getFormParameters().getFirst("rememberMe");
        boolean remember = rememberMe != null && rememberMe.equalsIgnoreCase("on");
        if (remember) {
            authenticationFlowContext.getAuthenticationSession().setAuthNote(Details.REMEMBER_ME, "true");
            authenticationFlowContext.getEvent().detail(Details.REMEMBER_ME, "true");
        } else {
            authenticationFlowContext.getAuthenticationSession().removeAuthNote(Details.REMEMBER_ME);
        }

        // all validation success
        log.info(" succesfully login for username : {} ", username);

        authenticationFlowContext.setUser(userModel);
        authenticationFlowContext.success();

        // check whether current IP is equals to previous IP
        /*
        List<String> ips = getLast2ip(username);
        if(!ips.isEmpty() && ips.size() >= 2) { // validate arraylist
            if(ips.get(0) !=null && ips.get(1) !=null) { // null checker
                if(!ips.get(0).equalsIgnoreCase(ips.get(1))) { // compare
                    // new ip
                    Thread thread = new Thread(){
                        public void run(){
                            try {
                                sendEmail(userModel, ips.get(0));
                            } catch (Exception ex) {
                                log.error(ex.getMessage(), ex);
                            }
                        }
                    };
                    thread.start();
                }
            }
        }
        */

        // capture the user-agent from header
        String agent = authenticationFlowContext.getHttpRequest().getHttpHeaders().getHeaderString(HttpHeaders.USER_AGENT);

        // check whether current IP is equals to previous 5 IP
        List<String> ips6 = getLast6ip(username);
        Boolean hasEqualsIp = false;
        if(!ips6.isEmpty() && ips6.size() >= 6) { // validate arraylist
            if (ips6.get(0) != null)  { // ip0 null checker
                for (int i = 1; i < 6; i++) {
                    if (ips6.get(i) != null) {
                        if (ips6.get(0).equalsIgnoreCase(ips6.get(i))) {
                            hasEqualsIp = true;
                        }
                    }
                }
                if (!hasEqualsIp) {
                    Thread thread = new Thread(){
                        public void run(){
                            try {
                                sendEmail(userModel, ips6.get(0), agent);
                            } catch (Exception ex) {
                                log.error(ex.getMessage(), ex);
                            }
                        }
                    };
                    thread.start();
                }
            }
        }

        // Update TnC to external API
        if (TncRestClient.tncApiBaseUrl != null && !TncRestClient.tncApiBaseUrl.trim().isEmpty()) {

            // Get statusTnc from UI
            String statusTncRaw = authenticationFlowContext.getHttpRequest().getFormParameters().getFirst("statusTnc");
            String statusTnc = statusTncRaw != null ? statusTncRaw.trim() : "";
            log.info("statusTnc from UI: {}", statusTnc);

            // Get current TnC user attribute
            /*
            List<String> tncAttrList = userModel.getAttributes().get(TNC_USER_ATTRIBUTE_KEY);
            String currentTncUserAttribute = null;
            if (tncAttrList != null && !tncAttrList.isEmpty() && tncAttrList.get(0) != null && !tncAttrList.get(0).isEmpty()) {
                currentTncUserAttribute = tncAttrList.get(0);
            }
            log.info("Current TnC User Attribute: {}", currentTncUserAttribute);
            */

            if (statusTnc.equals("0")) {

                TncRequest tncRequest = new TncRequest(userModel.getAttributes().get("orcluserid").get(0), "internal");

            Thread thread = new Thread() {
                public void run() {
                    try {
                        log.info("Calling UpdateUser API");
                        TncResponse tncResponse = TncRestClient.updateUser(tncRequest);
                        log.info("TNC API response: {}", new ObjectMapper().writeValueAsString(tncResponse));
                        
                        // Update user attribute tnc
                        /*
                        if (tncResponse != null 
                                && tncResponse.getData() != null 
                                && !tncResponse.getData().isEmpty() 
                                && tncResponse.getData().get(0) != null 
                                && tncResponse.getData().get(0).getTncTerbaruId() != null 
                                && !tncResponse.getData().get(0).getTncTerbaruId().isEmpty()) {
                            String tncUserAttribute = tncResponse.getData().get(0).getTncTerbaruId();
                            log.info("Updating TnC User Attribute: {}", tncUserAttribute);
                            userModel.setSingleAttribute(TNC_USER_ATTRIBUTE_KEY, tncUserAttribute);
                        }
                        */
                    } catch (Exception ex) {
                        log.error(ex.getMessage(), ex);
                    }
                }
            };
            thread.start();

            }
        }
    }

    public void action(AuthenticationFlowContext authenticationFlowContext) {
        authenticationFlowContext.success();
    }

    public boolean requiresUser() {
        return false;
    }

    public boolean configuredFor(KeycloakSession keycloakSession, RealmModel realmModel, UserModel userModel) {
        return false;
    }

    public void setRequiredActions(KeycloakSession keycloakSession, RealmModel realmModel, UserModel userModel) {
    }

    public void close() {

    }

    private boolean isUserAndOtpExist(String username, String otp) {
        ResultSet rs = null;
        PreparedStatement st = null;
        Connection c = null;

        try {
            c = PostgresDBHelper.getConnection();

            st = c.prepareStatement(Q_SEARCH_OTP);
            st.setString(1, username);
            st.setString(2, otp);
            st.execute();
            rs = st.getResultSet();

            boolean exists = rs.next();

            if(!exists) {
                log.info(" failed at isUserAndOtpExist username : {}, otp : {} ", username, otp);
            }

            return exists;
        } catch (SQLException ex) {
            throw new RuntimeException("Database error:" + ex.getMessage(), ex);
        } finally {
            PostgresDBHelper.closeQuietly(c);
            PostgresDBHelper.closeQuietly(rs);
            PostgresDBHelper.closeQuietly(st);
        }
    }

    private List<String> getLast2ip(String username) {
        ResultSet rs = null;
        PreparedStatement st = null;
        Connection c = null;

        List<String> ips = new ArrayList<>();

        try {
            c = PostgresDBHelper.getConnection();

            st = c.prepareStatement(Q_SEARCH_LAST_2_IP);
            st.setString(1, username);
            st.execute();
            rs = st.getResultSet();

            while(rs.next()) {
                ips.add(rs.getString("ip"));
            }

            return ips;
        } catch (SQLException ex) {
            throw new RuntimeException("Database error:" + ex.getMessage(), ex);
        } finally {
            PostgresDBHelper.closeQuietly(c);
            PostgresDBHelper.closeQuietly(rs);
            PostgresDBHelper.closeQuietly(st);
        }
    }

    private List<String> getLast6ip(String username) {
        ResultSet rs = null;
        PreparedStatement st = null;
        Connection c = null;

        List<String> ips = new ArrayList<>();

        try {
            c = PostgresDBHelper.getConnection();

            st = c.prepareStatement(Q_SEARCH_LAST_6_IP);
            st.setString(1, username);
            st.execute();
            rs = st.getResultSet();

            while(rs.next()) {
                ips.add(rs.getString("ip"));
            }

            return ips;
        } catch (SQLException ex) {
            throw new RuntimeException("Database error:" + ex.getMessage(), ex);
        } finally {
            PostgresDBHelper.closeQuietly(c);
            PostgresDBHelper.closeQuietly(rs);
            PostgresDBHelper.closeQuietly(st);
        }
    }

    private void updateOtp(String username, String otp, String kantor, String ip) {
        ResultSet rs = null;
        PreparedStatement st = null;
        Connection c = null;

        try {
            c = PostgresDBHelper.getConnection();

            st = c.prepareStatement(Q_UPDATE_OTP);
            st.setString(1, kantor);
            st.setString(2, ip);
            st.setString(3, username);
            st.setString(4, otp);
            st.executeUpdate();
        } catch (SQLException ex) {
            throw new RuntimeException("Database error:" + ex.getMessage(), ex);
        } finally {
            PostgresDBHelper.closeQuietly(c);
            PostgresDBHelper.closeQuietly(rs);
            PostgresDBHelper.closeQuietly(st);
        }
    }

    private boolean isUserAndKantorExist(String username, String kantor) {
        ResultSet rs = null;
        PreparedStatement st = null;
        Connection c = null;

        try {
            c = DBHelper.getConnection();

            st = c.prepareStatement(Q_VALIDATE_KANTOR);
            st.setString(1, username);
            st.setString(2, kantor);
            st.execute();
            rs = st.getResultSet();

            boolean exists = rs.next();

            if(!exists) {
                log.info(" failed at isUserAndKantorExist username : {}, kantor : {} ", username, kantor);
            }

            return exists;
        } catch (SQLException ex) {
            throw new RuntimeException("Database error:" + ex.getMessage(), ex);
        } finally {
            DBHelper.closeQuietly(c);
            DBHelper.closeQuietly(rs);
            DBHelper.closeQuietly(st);
        }
    }

    private void sendEmail(UserModel userModel, String ip, String agent) throws Exception {
        log.info("begin sending suspicious login email to {} - {}", userModel.getEmail(), userModel.getUsername());

        // check whether this user have an email field
        if(userModel.getEmail() == null || userModel.getEmail().trim().isEmpty()) {
            // empty email
            log.error("user {} have a null or empty email - unable to send suspicious email", userModel.getUsername());
            throw new Exception("have a null or empty email - unable to send suspicious email");
        } else {
            try {
                // validate email format
                new InternetAddress(userModel.getEmail());
            } catch (Exception ex) {
                // bad format email
                log.error("user {} have a bad email - unable to send suspicious email - {}", userModel.getUsername(), userModel.getEmail());
                throw new Exception("have a bad email - unable to send suspicious email");
            }
        }

        Properties props = System.getProperties();

        props.put("mail.smtp.starttls.enable", "true");
        props.put("mail.smtp.ssl.trust", smtpHost);
        props.put("mail.smtp.host", smtpHost);
        props.put("mail.smtp.port", "25");
        props.put("mail.smtp.auth", "false");

        Session session = Session.getInstance(props);
        MimeMessage message = new MimeMessage(session);

        message.setFrom(new InternetAddress(smtpFrom));
        message.addRecipient(Message.RecipientType.TO, new InternetAddress(userModel.getEmail()));

        Locale locale = new Locale("id", "ID");
        LocalDateTime now = LocalDateTime.now();
        String formattedDate = String.format(locale, "Hari %1$tA, tanggal %1$td %1$tB %1$tY, jam %1$tH:%1$tm", now);

        String emailBody = getEmailBody()
                .replace("FULL_NAME", userModel.getFirstName()+" "+userModel.getLastName())
                .replace("IP_ADDRESS", ip)
                .replace("FORMATED_DATE", formattedDate)
                .replace("BROWSER_NAME", getBrowserName(agent))
                .replace("DEVICE_NAME", getDeviceName(agent));
        message.setSubject("[ATR BPN] Informasi Login Aplikasi");
        message.setContent(emailBody,
                "text/html; charset=utf-8");
        Transport transport = session.getTransport("smtp");
        transport.connect();
        transport.sendMessage(message, message.getAllRecipients());
        transport.close();

        log.info("successfully sending suspicious login email to {} - {}", userModel.getEmail(), userModel.getUsername());
    }

    private String getEmailBody() {
        return "<html>\n" +
                "<head></head>\n" +
                "<body>\n" +
                "<img src=\"https://login.atrbpn.go.id/images/atrbpn-icon.png\" />\n" +
                "<p>Hai Sdr/i. FULL_NAME <br/>\n" +
                "di Tempat,</p>\n" +
                "\n" +
                "<p>Akun Aplikasi Kementerian ATR/BPN Anda baru saja login pada FORMATED_DATE \n" +
                "pada browser BROWSER_NAME, di perangkat DEVICE_NAME, dengan IP Address IP_ADDRESS.<br/>\n" +
                "Anda mendapatkan email ini untuk memastikan ini memang Anda. \n" +
                "Jika ini bukan Anda silahkan segera mengganti password untuk keamanan akun anda dengan klik tombol dibawah \n" +
                "atau pada link https://aplikasi.atrbpn.go.id/manajemen/akun/AkunSaya/GantiPassword </p>\n" +
                "<form action=\"https://aplikasi.atrbpn.go.id/manajemen/akun/AkunSaya/GantiPassword\" method=\"get\" target=\"_blank\"><button type=\"submit\">Ganti Password</button></form> \n" +
                "<p>~ Don't be a WEAKEST Link in the SECURITY Chain ~</p>\n" +
                "\n" +
                "<p>Salam,</p>\n" +
                "<p>Pengelola Aplikasi<br/>\n" +
                "Kementerian Agraria dan Tata Ruang / Badan Pertanahan Nasional</p>\n" +
                "</body>\n" +
                "</html>";
    }

    private String getBrowserName(String userAgent) {
        String result = "";

        String browserName = userAgent.toLowerCase();
        String msieRegx = ".*msie.*";
        String operaRegx = ".*opera.*";
        String firefoxRegx = ".*firefox.*";
        String chromeRegx = ".*chrome.*";
        String webkitRegx = ".*webkit.*";
        String mozillaRegx = ".*mozilla.*";
        String safariRegx = ".*safari.*";

        if (Pattern.matches(msieRegx, browserName)
                && !Pattern.matches(operaRegx, browserName)) {
            result = "IE";
        } else if (Pattern.matches(firefoxRegx, browserName)) {
            result = "Firefox";
        } else if (Pattern.matches(chromeRegx, browserName)
                && Pattern.matches(webkitRegx, browserName)
                && Pattern.matches(mozillaRegx, browserName)) {
            result = "Chrome";
        } else if (Pattern.matches(operaRegx, browserName)) {
            result = "Opera";
        } else if (Pattern.matches(safariRegx, browserName)
                && !Pattern.matches(chromeRegx, browserName)
                && Pattern.matches(webkitRegx, browserName)
                && Pattern.matches(mozillaRegx, browserName)) {
            result = "Safari";
        } else {
            result = "unknown";
        }

        return result;
    }

    private String getDeviceName(String userAgent) {
        String result = "unknown";

        // Pattern pattern = Pattern.compile("(?<=\\()[^\\s]+");
        Pattern pattern = Pattern.compile("(?<=\\().*?(?=\\))");
        Matcher matcher = pattern.matcher(userAgent);
        if (matcher.find()) {
            result = matcher.group();
        }

        return result;
    }

    private List<String> getRoles(String username, String kantor) {
        log.info("begin querying roles for {} - kantor {}", username, kantor);
        ResultSet rs = null;
        PreparedStatement st = null;
        Connection c = null;

        List<String> roles = new ArrayList<>();
        try {
            c = DBHelper.getConnection();

            st = c.prepareStatement(Q_GET_ROLES);
            st.setString(1, username);
            st.setString(2, kantor);
            st.execute();
            rs = st.getResultSet();

            while (rs.next()) {
                String role = rs.getString(1);
                if(role != null) {
                    roles.add(role);
                }
            }

        } catch (SQLException ex) {
            throw new RuntimeException("Database error:" + ex.getMessage(), ex);
        } finally {
            DBHelper.closeQuietly(c);
            DBHelper.closeQuietly(rs);
            DBHelper.closeQuietly(st);

            log.info("finish querying roles for {} - kantor {}", username, kantor);
        }

        return roles;
    }
}
